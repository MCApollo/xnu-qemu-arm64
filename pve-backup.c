#include "proxmox-backup-client.h"
#include "vma.h"

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "sysemu/block-backend.h"
#include "sysemu/blockdev.h"
#include "block/blockjob.h"
#include "qapi/qapi-commands-block.h"
#include "qapi/qmp/qerror.h"

/* PVE backup state and related function */

/*
 * Note: A resume from a qemu_coroutine_yield can happen in a different thread,
 * so you may not use normal mutexes within coroutines:
 *
 * ---bad-example---
 * qemu_rec_mutex_lock(lock)
 * ...
 * qemu_coroutine_yield() // wait for something
 * // we are now inside a different thread
 * qemu_rec_mutex_unlock(lock) // Crash - wrong thread!!
 * ---end-bad-example--
 *
 * ==> Always use CoMutext inside coroutines.
 * ==> Never acquire/release AioContext withing coroutines (because that use QemuRecMutex)
 *
 */

const char *PBS_BITMAP_NAME = "pbs-incremental-dirty-bitmap";

static struct PVEBackupState {
    struct {
        // Everithing accessed from qmp_backup_query command is protected using lock
        QemuMutex lock;
        Error *error;
        time_t start_time;
        time_t end_time;
        char *backup_file;
        uuid_t uuid;
        char uuid_str[37];
        size_t total;
        size_t dirty;
        size_t transferred;
        size_t reused;
        size_t zero_bytes;
    } stat;
    int64_t speed;
    VmaWriter *vmaw;
    ProxmoxBackupHandle *pbs;
    GList *di_list;
    QemuMutex backup_mutex;
    CoMutex dump_callback_mutex;
} backup_state;

static void pvebackup_init(void)
{
    qemu_mutex_init(&backup_state.stat.lock);
    qemu_mutex_init(&backup_state.backup_mutex);
    qemu_co_mutex_init(&backup_state.dump_callback_mutex);
}

// initialize PVEBackupState at startup
opts_init(pvebackup_init);

typedef struct PVEBackupDevInfo {
    BlockDriverState *bs;
    size_t size;
    uint8_t dev_id;
    bool completed;
    char targetfile[PATH_MAX];
    BdrvDirtyBitmap *bitmap;
    BlockDriverState *target;
} PVEBackupDevInfo;

static void pvebackup_run_next_job(void);

static BlockJob *
lookup_active_block_job(PVEBackupDevInfo *di)
{
    if (!di->completed && di->bs) {
        for (BlockJob *job = block_job_next(NULL); job; job = block_job_next(job)) {
            if (job->job.driver->job_type != JOB_TYPE_BACKUP) {
                continue;
            }

            BackupBlockJob *bjob = container_of(job, BackupBlockJob, common);
            if (bjob && bjob->source_bs == di->bs) {
                return job;
            }
        }
    }
    return NULL;
}

static void pvebackup_propagate_error(Error *err)
{
    qemu_mutex_lock(&backup_state.stat.lock);
    error_propagate(&backup_state.stat.error, err);
    qemu_mutex_unlock(&backup_state.stat.lock);
}

static bool pvebackup_error_or_canceled(void)
{
    qemu_mutex_lock(&backup_state.stat.lock);
    bool error_or_canceled = !!backup_state.stat.error;
    qemu_mutex_unlock(&backup_state.stat.lock);

    return error_or_canceled;
}

static void pvebackup_add_transfered_bytes(size_t transferred, size_t zero_bytes, size_t reused)
{
    qemu_mutex_lock(&backup_state.stat.lock);
    backup_state.stat.zero_bytes += zero_bytes;
    backup_state.stat.transferred += transferred;
    backup_state.stat.reused += reused;
    qemu_mutex_unlock(&backup_state.stat.lock);
}

// This may get called from multiple coroutines in multiple io-threads
// Note1: this may get called after job_cancel()
static int coroutine_fn
pvebackup_co_dump_pbs_cb(
    void *opaque,
    uint64_t start,
    uint64_t bytes,
    const void *pbuf)
{
    assert(qemu_in_coroutine());

    const uint64_t size = bytes;
    const unsigned char *buf = pbuf;
    PVEBackupDevInfo *di = opaque;

    assert(backup_state.pbs);

    Error *local_err = NULL;
    int pbs_res = -1;

    qemu_co_mutex_lock(&backup_state.dump_callback_mutex);

    // avoid deadlock if job is cancelled
    if (pvebackup_error_or_canceled()) {
        qemu_co_mutex_unlock(&backup_state.dump_callback_mutex);
        return -1;
    }

    pbs_res = proxmox_backup_co_write_data(backup_state.pbs, di->dev_id, buf, start, size, &local_err);
    qemu_co_mutex_unlock(&backup_state.dump_callback_mutex);

    if (pbs_res < 0) {
        pvebackup_propagate_error(local_err);
        return pbs_res;
    } else {
        size_t reused = (pbs_res == 0) ? size : 0;
        pvebackup_add_transfered_bytes(size, !buf ? size : 0, reused);
    }

    return size;
}

// This may get called from multiple coroutines in multiple io-threads
static int coroutine_fn
pvebackup_co_dump_vma_cb(
    void *opaque,
    uint64_t start,
    uint64_t bytes,
    const void *pbuf)
{
    assert(qemu_in_coroutine());

    const uint64_t size = bytes;
    const unsigned char *buf = pbuf;
    PVEBackupDevInfo *di = opaque;

    int ret = -1;

    assert(backup_state.vmaw);

    uint64_t remaining = size;

    uint64_t cluster_num = start / VMA_CLUSTER_SIZE;
    if ((cluster_num * VMA_CLUSTER_SIZE) != start) {
        Error *local_err = NULL;
        error_setg(&local_err,
                   "got unaligned write inside backup dump "
                   "callback (sector %ld)", start);
        pvebackup_propagate_error(local_err);
        return -1; // not aligned to cluster size
    }

    while (remaining > 0) {
        qemu_co_mutex_lock(&backup_state.dump_callback_mutex);
        // avoid deadlock if job is cancelled
        if (pvebackup_error_or_canceled()) {
            qemu_co_mutex_unlock(&backup_state.dump_callback_mutex);
            return -1;
        }

        size_t zero_bytes = 0;
        ret = vma_writer_write(backup_state.vmaw, di->dev_id, cluster_num, buf, &zero_bytes);
        qemu_co_mutex_unlock(&backup_state.dump_callback_mutex);

        ++cluster_num;
        if (buf) {
            buf += VMA_CLUSTER_SIZE;
        }
        if (ret < 0) {
            Error *local_err = NULL;
            vma_writer_error_propagate(backup_state.vmaw, &local_err);
            pvebackup_propagate_error(local_err);
            return ret;
        } else {
            if (remaining >= VMA_CLUSTER_SIZE) {
                assert(ret == VMA_CLUSTER_SIZE);
                pvebackup_add_transfered_bytes(VMA_CLUSTER_SIZE, zero_bytes, 0);
                remaining -= VMA_CLUSTER_SIZE;
            } else {
                assert(ret == remaining);
                pvebackup_add_transfered_bytes(remaining, zero_bytes, 0);
                remaining = 0;
            }
        }
    }

    return size;
}

// assumes the caller holds backup_mutex
static void coroutine_fn pvebackup_co_cleanup(void *unused)
{
    assert(qemu_in_coroutine());

    qemu_mutex_lock(&backup_state.stat.lock);
    backup_state.stat.end_time = time(NULL);
    qemu_mutex_unlock(&backup_state.stat.lock);

    if (backup_state.vmaw) {
        Error *local_err = NULL;
        vma_writer_close(backup_state.vmaw, &local_err);

        if (local_err != NULL) {
            pvebackup_propagate_error(local_err);
         }

        backup_state.vmaw = NULL;
    }

    if (backup_state.pbs) {
        if (!pvebackup_error_or_canceled()) {
            Error *local_err = NULL;
            proxmox_backup_co_finish(backup_state.pbs, &local_err);
            if (local_err != NULL) {
                pvebackup_propagate_error(local_err);
            }
        } else {
            // on error or cancel we cannot ensure synchronization of dirty
            // bitmaps with backup server, so remove all and do full backup next
            GList *l = backup_state.di_list;
            while (l) {
                PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
                l = g_list_next(l);

                if (di->bitmap) {
                    bdrv_release_dirty_bitmap(di->bitmap);
                }
            }
        }

        proxmox_backup_disconnect(backup_state.pbs);
        backup_state.pbs = NULL;
    }

    g_list_free(backup_state.di_list);
    backup_state.di_list = NULL;
}

// assumes the caller holds backup_mutex
static void coroutine_fn pvebackup_complete_stream(void *opaque)
{
    PVEBackupDevInfo *di = opaque;

    bool error_or_canceled = pvebackup_error_or_canceled();

    if (backup_state.vmaw) {
        vma_writer_close_stream(backup_state.vmaw, di->dev_id);
    }

    if (backup_state.pbs && !error_or_canceled) {
        Error *local_err = NULL;
        proxmox_backup_co_close_image(backup_state.pbs, di->dev_id, &local_err);
        if (local_err != NULL) {
            pvebackup_propagate_error(local_err);
        }
    }
}

static void pvebackup_complete_cb(void *opaque, int ret)
{
    assert(!qemu_in_coroutine());

    PVEBackupDevInfo *di = opaque;

    qemu_mutex_lock(&backup_state.backup_mutex);

    di->completed = true;

    if (ret < 0) {
        Error *local_err = NULL;
        error_setg(&local_err, "job failed with err %d - %s", ret, strerror(-ret));
        pvebackup_propagate_error(local_err);
    }

    di->bs = NULL;

    assert(di->target == NULL);

    block_on_coroutine_fn(pvebackup_complete_stream, di);

    // remove self from job queue
    backup_state.di_list = g_list_remove(backup_state.di_list, di);

    if (di->bitmap && ret < 0) {
        // on error or cancel we cannot ensure synchronization of dirty
        // bitmaps with backup server, so remove all and do full backup next
        bdrv_release_dirty_bitmap(di->bitmap);
    }

    g_free(di);

    qemu_mutex_unlock(&backup_state.backup_mutex);

    pvebackup_run_next_job();
}

static void pvebackup_cancel(void)
{
    assert(!qemu_in_coroutine());

    Error *cancel_err = NULL;
    error_setg(&cancel_err, "backup canceled");
    pvebackup_propagate_error(cancel_err);

    qemu_mutex_lock(&backup_state.backup_mutex);

    if (backup_state.vmaw) {
        /* make sure vma writer does not block anymore */
        vma_writer_set_error(backup_state.vmaw, "backup canceled");
    }

    if (backup_state.pbs) {
        proxmox_backup_abort(backup_state.pbs, "backup canceled");
    }

    qemu_mutex_unlock(&backup_state.backup_mutex);

    for(;;) {

        BlockJob *next_job = NULL;

        qemu_mutex_lock(&backup_state.backup_mutex);

        GList *l = backup_state.di_list;
        while (l) {
            PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
            l = g_list_next(l);

            BlockJob *job = lookup_active_block_job(di);
            if (job != NULL) {
                next_job = job;
                break;
            }
        }

        qemu_mutex_unlock(&backup_state.backup_mutex);

        if (next_job) {
            AioContext *aio_context = next_job->job.aio_context;
            aio_context_acquire(aio_context);
            job_cancel_sync(&next_job->job);
            aio_context_release(aio_context);
        } else {
            break;
        }
    }
}

void qmp_backup_cancel(Error **errp)
{
    pvebackup_cancel();
}

// assumes the caller holds backup_mutex
static int coroutine_fn pvebackup_co_add_config(
    const char *file,
    const char *name,
    BackupFormat format,
    const char *backup_dir,
    VmaWriter *vmaw,
    ProxmoxBackupHandle *pbs,
    Error **errp)
{
    int res = 0;

    char *cdata = NULL;
    gsize clen = 0;
    GError *err = NULL;
    if (!g_file_get_contents(file, &cdata, &clen, &err)) {
        error_setg(errp, "unable to read file '%s'", file);
        return 1;
    }

    char *basename = g_path_get_basename(file);
    if (name == NULL) name = basename;

    if (format == BACKUP_FORMAT_VMA) {
        if (vma_writer_add_config(vmaw, name, cdata, clen) != 0) {
            error_setg(errp, "unable to add %s config data to vma archive", file);
            goto err;
        }
    } else if (format == BACKUP_FORMAT_PBS) {
        if (proxmox_backup_co_add_config(pbs, name, (unsigned char *)cdata, clen, errp) < 0)
            goto err;
    } else if (format == BACKUP_FORMAT_DIR) {
        char config_path[PATH_MAX];
        snprintf(config_path, PATH_MAX, "%s/%s", backup_dir, name);
        if (!g_file_set_contents(config_path, cdata, clen, &err)) {
            error_setg(errp, "unable to write config file '%s'", config_path);
            goto err;
        }
    }

 out:
    g_free(basename);
    g_free(cdata);
    return res;

 err:
    res = -1;
    goto out;
}

bool job_should_pause(Job *job);

static void pvebackup_run_next_job(void)
{
    assert(!qemu_in_coroutine());

    qemu_mutex_lock(&backup_state.backup_mutex);

    GList *l = backup_state.di_list;
    while (l) {
        PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
        l = g_list_next(l);

        BlockJob *job = lookup_active_block_job(di);

        if (job) {
            qemu_mutex_unlock(&backup_state.backup_mutex);

            AioContext *aio_context = job->job.aio_context;
            aio_context_acquire(aio_context);

            if (job_should_pause(&job->job)) {
                bool error_or_canceled = pvebackup_error_or_canceled();
                if (error_or_canceled) {
                    job_cancel_sync(&job->job);
                } else {
                    job_resume(&job->job);
                }
            }
            aio_context_release(aio_context);
            return;
        }
    }

    block_on_coroutine_fn(pvebackup_co_cleanup, NULL); // no more jobs, run cleanup

    qemu_mutex_unlock(&backup_state.backup_mutex);
}

static bool create_backup_jobs(void) {

    assert(!qemu_in_coroutine());

    Error *local_err = NULL;

    /* create and start all jobs (paused state) */
    GList *l =  backup_state.di_list;
    while (l) {
        PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
        l = g_list_next(l);

        assert(di->target != NULL);

        MirrorSyncMode sync_mode = MIRROR_SYNC_MODE_FULL;
        BitmapSyncMode bitmap_mode = BITMAP_SYNC_MODE_NEVER;
        if (di->bitmap) {
            sync_mode = MIRROR_SYNC_MODE_BITMAP;
            bitmap_mode = BITMAP_SYNC_MODE_ON_SUCCESS;
        }
        AioContext *aio_context = bdrv_get_aio_context(di->bs);
        aio_context_acquire(aio_context);

        BlockJob *job = backup_job_create(
            NULL, di->bs, di->target, backup_state.speed, sync_mode, di->bitmap,
            bitmap_mode, false, NULL, BLOCKDEV_ON_ERROR_REPORT, BLOCKDEV_ON_ERROR_REPORT,
            JOB_DEFAULT, pvebackup_complete_cb, di, 1, NULL, &local_err);

        aio_context_release(aio_context);

        if (!job || local_err != NULL) {
            Error *create_job_err = NULL;
            error_setg(&create_job_err, "backup_job_create failed: %s",
                       local_err ? error_get_pretty(local_err) : "null");

            pvebackup_propagate_error(create_job_err);
            break;
        }
        job_start(&job->job);

        bdrv_unref(di->target);
        di->target = NULL;
    }

    bool errors = pvebackup_error_or_canceled();

    if (errors) {
        l = backup_state.di_list;
        while (l) {
            PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
            l = g_list_next(l);

            if (di->target) {
                bdrv_unref(di->target);
                di->target = NULL;
            }
        }
    }

    return errors;
}

typedef struct QmpBackupTask {
    const char *backup_file;
    bool has_password;
    const char *password;
    bool has_keyfile;
    const char *keyfile;
    bool has_key_password;
    const char *key_password;
    bool has_backup_id;
    const char *backup_id;
    bool has_backup_time;
    const char *fingerprint;
    bool has_fingerprint;
    int64_t backup_time;
    bool has_use_dirty_bitmap;
    bool use_dirty_bitmap;
    bool has_format;
    BackupFormat format;
    bool has_config_file;
    const char *config_file;
    bool has_firewall_file;
    const char *firewall_file;
    bool has_devlist;
    const char *devlist;
    bool has_compress;
    bool compress;
    bool has_encrypt;
    bool encrypt;
    bool has_speed;
    int64_t speed;
    Error **errp;
    UuidInfo *result;
} QmpBackupTask;

// assumes the caller holds backup_mutex
static void coroutine_fn pvebackup_co_prepare(void *opaque)
{
    assert(qemu_in_coroutine());

    QmpBackupTask *task = opaque;

    task->result = NULL; // just to be sure

    BlockBackend *blk;
    BlockDriverState *bs = NULL;
    const char *backup_dir = NULL;
    Error *local_err = NULL;
    uuid_t uuid;
    VmaWriter *vmaw = NULL;
    ProxmoxBackupHandle *pbs = NULL;
    gchar **devs = NULL;
    GList *di_list = NULL;
    GList *l;
    UuidInfo *uuid_info;

    const char *config_name = "qemu-server.conf";
    const char *firewall_name = "qemu-server.fw";

    if (backup_state.di_list) {
         error_set(task->errp, ERROR_CLASS_GENERIC_ERROR,
                  "previous backup not finished");
        return;
    }

    /* Todo: try to auto-detect format based on file name */
    BackupFormat format = task->has_format ? task->format : BACKUP_FORMAT_VMA;

    if (task->has_devlist) {
        devs = g_strsplit_set(task->devlist, ",;:", -1);

        gchar **d = devs;
        while (d && *d) {
            blk = blk_by_name(*d);
            if (blk) {
                bs = blk_bs(blk);
                if (bdrv_is_read_only(bs)) {
                    error_setg(task->errp, "Node '%s' is read only", *d);
                    goto err;
                }
                if (!bdrv_is_inserted(bs)) {
                    error_setg(task->errp, QERR_DEVICE_HAS_NO_MEDIUM, *d);
                    goto err;
                }
                PVEBackupDevInfo *di = g_new0(PVEBackupDevInfo, 1);
                di->bs = bs;
                di_list = g_list_append(di_list, di);
            } else {
                error_set(task->errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                          "Device '%s' not found", *d);
                goto err;
            }
            d++;
        }

    } else {
        BdrvNextIterator it;

        bs = NULL;
        for (bs = bdrv_first(&it); bs; bs = bdrv_next(&it)) {
            if (!bdrv_is_inserted(bs) || bdrv_is_read_only(bs)) {
                continue;
            }

            PVEBackupDevInfo *di = g_new0(PVEBackupDevInfo, 1);
            di->bs = bs;
            di_list = g_list_append(di_list, di);
        }
    }

    if (!di_list) {
        error_set(task->errp, ERROR_CLASS_GENERIC_ERROR, "empty device list");
        goto err;
    }

    size_t total = 0;
    size_t dirty = 0;

    l = di_list;
    while (l) {
        PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
        l = g_list_next(l);
        if (bdrv_op_is_blocked(di->bs, BLOCK_OP_TYPE_BACKUP_SOURCE, task->errp)) {
            goto err;
        }

        ssize_t size = bdrv_getlength(di->bs);
        if (size < 0) {
            error_setg_errno(task->errp, -di->size, "bdrv_getlength failed");
            goto err;
        }
        di->size = size;
        total += size;
    }

    uuid_generate(uuid);

    if (format == BACKUP_FORMAT_PBS) {
        if (!task->has_password) {
            error_set(task->errp, ERROR_CLASS_GENERIC_ERROR, "missing parameter 'password'");
            goto err;
        }
        if (!task->has_backup_id) {
            error_set(task->errp, ERROR_CLASS_GENERIC_ERROR, "missing parameter 'backup-id'");
            goto err;
        }
        if (!task->has_backup_time) {
            error_set(task->errp, ERROR_CLASS_GENERIC_ERROR, "missing parameter 'backup-time'");
            goto err;
        }

        int dump_cb_block_size = PROXMOX_BACKUP_DEFAULT_CHUNK_SIZE; // Hardcoded (4M)
        firewall_name = "fw.conf";

        bool use_dirty_bitmap = task->has_use_dirty_bitmap && task->use_dirty_bitmap;


        char *pbs_err = NULL;
        pbs = proxmox_backup_new(
            task->backup_file,
            task->backup_id,
            task->backup_time,
            dump_cb_block_size,
            task->has_password ? task->password : NULL,
            task->has_keyfile ? task->keyfile : NULL,
            task->has_key_password ? task->key_password : NULL,
            task->has_compress ? task->compress : true,
            task->has_encrypt ? task->encrypt : task->has_keyfile,
            task->has_fingerprint ? task->fingerprint : NULL,
             &pbs_err);

        if (!pbs) {
            error_set(task->errp, ERROR_CLASS_GENERIC_ERROR,
                      "proxmox_backup_new failed: %s", pbs_err);
            proxmox_backup_free_error(pbs_err);
            goto err;
        }

        int connect_result = proxmox_backup_co_connect(pbs, task->errp);
        if (connect_result < 0)
            goto err;

        /* register all devices */
        l = di_list;
        while (l) {
            PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
            l = g_list_next(l);

            const char *devname = bdrv_get_device_name(di->bs);

            BdrvDirtyBitmap *bitmap = bdrv_find_dirty_bitmap(di->bs, PBS_BITMAP_NAME);
            bool expect_only_dirty = false;

            if (use_dirty_bitmap) {
                if (bitmap == NULL) {
                    bitmap = bdrv_create_dirty_bitmap(di->bs, dump_cb_block_size, PBS_BITMAP_NAME, task->errp);
                    if (!bitmap) {
                        goto err;
                    }
                } else {
                    expect_only_dirty = proxmox_backup_check_incremental(pbs, devname, di->size) != 0;
                }

                if (expect_only_dirty) {
                    dirty += bdrv_get_dirty_count(bitmap);
                } else {
                    /* mark entire bitmap as dirty to make full backup */
                    bdrv_set_dirty_bitmap(bitmap, 0, di->size);
                    dirty += di->size;
                }
                di->bitmap = bitmap;
            } else {
                dirty += di->size;

                /* after a full backup the old dirty bitmap is invalid anyway */
                if (bitmap != NULL) {
                    bdrv_release_dirty_bitmap(bitmap);
                }
            }

            int dev_id = proxmox_backup_co_register_image(pbs, devname, di->size, expect_only_dirty, task->errp);
            if (dev_id < 0) {
                goto err;
            }

            if (!(di->target = bdrv_backup_dump_create(dump_cb_block_size, di->size, pvebackup_co_dump_pbs_cb, di, task->errp))) {
                goto err;
            }

            di->dev_id = dev_id;
        }
    } else if (format == BACKUP_FORMAT_VMA) {
        dirty = total;

        vmaw = vma_writer_create(task->backup_file, uuid, &local_err);
        if (!vmaw) {
            if (local_err) {
                error_propagate(task->errp, local_err);
            }
            goto err;
        }

        /* register all devices for vma writer */
        l = di_list;
        while (l) {
            PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
            l = g_list_next(l);

            if (!(di->target = bdrv_backup_dump_create(VMA_CLUSTER_SIZE, di->size, pvebackup_co_dump_vma_cb, di, task->errp))) {
                goto err;
            }

            const char *devname = bdrv_get_device_name(di->bs);
            di->dev_id = vma_writer_register_stream(vmaw, devname, di->size);
            if (di->dev_id <= 0) {
                error_set(task->errp, ERROR_CLASS_GENERIC_ERROR,
                          "register_stream failed");
                goto err;
            }
        }
    } else if (format == BACKUP_FORMAT_DIR) {
        dirty = total;

        if (mkdir(task->backup_file, 0640) != 0) {
            error_setg_errno(task->errp, errno, "can't create directory '%s'\n",
                             task->backup_file);
            goto err;
        }
        backup_dir = task->backup_file;

        l = di_list;
        while (l) {
            PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
            l = g_list_next(l);

            const char *devname = bdrv_get_device_name(di->bs);
            snprintf(di->targetfile, PATH_MAX, "%s/%s.raw", backup_dir, devname);

            int flags = BDRV_O_RDWR;
            bdrv_img_create(di->targetfile, "raw", NULL, NULL, NULL,
                            di->size, flags, false, &local_err);
            if (local_err) {
                error_propagate(task->errp, local_err);
                goto err;
            }

            di->target = bdrv_open(di->targetfile, NULL, NULL, flags, &local_err);
            if (!di->target) {
                error_propagate(task->errp, local_err);
                goto err;
            }
        }
    } else {
        error_set(task->errp, ERROR_CLASS_GENERIC_ERROR, "unknown backup format");
        goto err;
    }


    /* add configuration file to archive */
    if (task->has_config_file) {
        if (pvebackup_co_add_config(task->config_file, config_name, format, backup_dir,
                                    vmaw, pbs, task->errp) != 0) {
            goto err;
        }
    }

    /* add firewall file to archive */
    if (task->has_firewall_file) {
        if (pvebackup_co_add_config(task->firewall_file, firewall_name, format, backup_dir,
                                    vmaw, pbs, task->errp) != 0) {
            goto err;
        }
    }
    /* initialize global backup_state now */

    qemu_mutex_lock(&backup_state.stat.lock);

    if (backup_state.stat.error) {
        error_free(backup_state.stat.error);
        backup_state.stat.error = NULL;
    }

    backup_state.stat.start_time = time(NULL);
    backup_state.stat.end_time = 0;

    if (backup_state.stat.backup_file) {
        g_free(backup_state.stat.backup_file);
    }
    backup_state.stat.backup_file = g_strdup(task->backup_file);

    uuid_copy(backup_state.stat.uuid, uuid);
    uuid_unparse_lower(uuid, backup_state.stat.uuid_str);
    char *uuid_str = g_strdup(backup_state.stat.uuid_str);

    backup_state.stat.total = total;
    backup_state.stat.dirty = dirty;
    backup_state.stat.transferred = 0;
    backup_state.stat.zero_bytes = 0;
    backup_state.stat.reused = format == BACKUP_FORMAT_PBS && dirty >= total ? 0 : total - dirty;

    qemu_mutex_unlock(&backup_state.stat.lock);

    backup_state.speed = (task->has_speed && task->speed > 0) ? task->speed : 0;

    backup_state.vmaw = vmaw;
    backup_state.pbs = pbs;

    backup_state.di_list = di_list;

    uuid_info = g_malloc0(sizeof(*uuid_info));
    uuid_info->UUID = uuid_str;

    task->result = uuid_info;
    return;

err:

    l = di_list;
    while (l) {
        PVEBackupDevInfo *di = (PVEBackupDevInfo *)l->data;
        l = g_list_next(l);

        if (di->bitmap) {
            bdrv_release_dirty_bitmap(di->bitmap);
        }

        if (di->target) {
            bdrv_unref(di->target);
        }

        if (di->targetfile[0]) {
            unlink(di->targetfile);
        }
        g_free(di);
    }
    g_list_free(di_list);

    if (devs) {
        g_strfreev(devs);
    }

    if (vmaw) {
        Error *err = NULL;
        vma_writer_close(vmaw, &err);
        unlink(task->backup_file);
    }

    if (pbs) {
        proxmox_backup_disconnect(pbs);
    }

    if (backup_dir) {
        rmdir(backup_dir);
    }

    task->result = NULL;
    return;
}

UuidInfo *qmp_backup(
    const char *backup_file,
    bool has_password, const char *password,
    bool has_keyfile, const char *keyfile,
    bool has_key_password, const char *key_password,
    bool has_fingerprint, const char *fingerprint,
    bool has_backup_id, const char *backup_id,
    bool has_backup_time, int64_t backup_time,
    bool has_use_dirty_bitmap, bool use_dirty_bitmap,
    bool has_compress, bool compress,
    bool has_encrypt, bool encrypt,
    bool has_format, BackupFormat format,
    bool has_config_file, const char *config_file,
    bool has_firewall_file, const char *firewall_file,
    bool has_devlist, const char *devlist,
    bool has_speed, int64_t speed, Error **errp)
{
    QmpBackupTask task = {
        .backup_file = backup_file,
        .has_password = has_password,
        .password = password,
        .has_keyfile = has_keyfile,
        .keyfile = keyfile,
        .has_key_password = has_key_password,
        .key_password = key_password,
        .has_fingerprint = has_fingerprint,
        .fingerprint = fingerprint,
        .has_backup_id = has_backup_id,
        .backup_id = backup_id,
        .has_backup_time = has_backup_time,
        .backup_time = backup_time,
        .has_use_dirty_bitmap = has_use_dirty_bitmap,
        .use_dirty_bitmap = use_dirty_bitmap,
        .has_compress = has_compress,
        .compress = compress,
        .has_encrypt = has_encrypt,
        .encrypt = encrypt,
        .has_format = has_format,
        .format = format,
        .has_config_file = has_config_file,
        .config_file = config_file,
        .has_firewall_file = has_firewall_file,
        .firewall_file = firewall_file,
        .has_devlist = has_devlist,
        .devlist = devlist,
        .has_speed = has_speed,
        .speed = speed,
        .errp = errp,
    };

    qemu_mutex_lock(&backup_state.backup_mutex);

    block_on_coroutine_fn(pvebackup_co_prepare, &task);

    if (*errp == NULL) {
        create_backup_jobs();
        qemu_mutex_unlock(&backup_state.backup_mutex);
        pvebackup_run_next_job();
    } else {
        qemu_mutex_unlock(&backup_state.backup_mutex);
    }

    return task.result;
}

BackupStatus *qmp_query_backup(Error **errp)
{
    BackupStatus *info = g_malloc0(sizeof(*info));

    qemu_mutex_lock(&backup_state.stat.lock);

    if (!backup_state.stat.start_time) {
        /* not started, return {} */
        qemu_mutex_unlock(&backup_state.stat.lock);
        return info;
    }

    info->has_status = true;
    info->has_start_time = true;
    info->start_time = backup_state.stat.start_time;

    if (backup_state.stat.backup_file) {
        info->has_backup_file = true;
        info->backup_file = g_strdup(backup_state.stat.backup_file);
    }

    info->has_uuid = true;
    info->uuid = g_strdup(backup_state.stat.uuid_str);

    if (backup_state.stat.end_time) {
        if (backup_state.stat.error) {
            info->status = g_strdup("error");
            info->has_errmsg = true;
            info->errmsg = g_strdup(error_get_pretty(backup_state.stat.error));
        } else {
            info->status = g_strdup("done");
        }
        info->has_end_time = true;
        info->end_time = backup_state.stat.end_time;
    } else {
        info->status = g_strdup("active");
    }

    info->has_total = true;
    info->total = backup_state.stat.total;
    info->has_dirty = true;
    info->dirty = backup_state.stat.dirty;
    info->has_zero_bytes = true;
    info->zero_bytes = backup_state.stat.zero_bytes;
    info->has_transferred = true;
    info->transferred = backup_state.stat.transferred;
    info->has_reused = true;
    info->reused = backup_state.stat.reused;

    qemu_mutex_unlock(&backup_state.stat.lock);

    return info;
}

ProxmoxSupportStatus *qmp_query_proxmox_support(Error **errp)
{
    ProxmoxSupportStatus *ret = g_malloc0(sizeof(*ret));
    ret->pbs_dirty_bitmap = true;
    return ret;
}
