/*
 * Proxmox Backup Server read-only block driver
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/cutils.h"
#include "block/block_int.h"

#include <proxmox-backup-qemu.h>

#define PBS_OPT_REPOSITORY "repository"
#define PBS_OPT_SNAPSHOT "snapshot"
#define PBS_OPT_ARCHIVE "archive"
#define PBS_OPT_KEYFILE "keyfile"
#define PBS_OPT_PASSWORD "password"
#define PBS_OPT_FINGERPRINT "fingerprint"
#define PBS_OPT_ENCRYPTION_PASSWORD "key_password"

typedef struct {
    ProxmoxRestoreHandle *conn;
    char aid;
    int64_t length;

    char *repository;
    char *snapshot;
    char *archive;
} BDRVPBSState;

static QemuOptsList runtime_opts = {
    .name = "pbs",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = PBS_OPT_REPOSITORY,
            .type = QEMU_OPT_STRING,
            .help = "The server address and repository to connect to.",
        },
        {
            .name = PBS_OPT_SNAPSHOT,
            .type = QEMU_OPT_STRING,
            .help = "The snapshot to read.",
        },
        {
            .name = PBS_OPT_ARCHIVE,
            .type = QEMU_OPT_STRING,
            .help = "Which archive within the snapshot should be accessed.",
        },
        {
            .name = PBS_OPT_PASSWORD,
            .type = QEMU_OPT_STRING,
            .help = "Server password. Can be passed as env var 'PBS_PASSWORD'.",
        },
        {
            .name = PBS_OPT_FINGERPRINT,
            .type = QEMU_OPT_STRING,
            .help = "Server fingerprint. Can be passed as env var 'PBS_FINGERPRINT'.",
        },
        {
            .name = PBS_OPT_ENCRYPTION_PASSWORD,
            .type = QEMU_OPT_STRING,
            .help = "Optional: Key password. Can be passed as env var 'PBS_ENCRYPTION_PASSWORD'.",
        },
        {
            .name = PBS_OPT_KEYFILE,
            .type = QEMU_OPT_STRING,
            .help = "Optional: The path to the keyfile to use.",
        },
        { /* end of list */ }
    },
};


// filename format:
// pbs:repository=<repo>,snapshot=<snap>,password=<pw>,key_password=<kpw>,fingerprint=<fp>,archive=<archive>
static void pbs_parse_filename(const char *filename, QDict *options,
                                     Error **errp)
{

    if (!strstart(filename, "pbs:", &filename)) {
        if (errp) error_setg(errp, "pbs_parse_filename failed - missing 'pbs:' prefix");
    }


    QemuOpts *opts = qemu_opts_parse_noisily(&runtime_opts, filename, false);
    if (!opts) {
        if (errp) error_setg(errp, "pbs_parse_filename failed");
        return;
    }

    qemu_opts_to_qdict(opts, options);

    qemu_opts_del(opts);
}

static int pbs_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    QemuOpts *opts;
    BDRVPBSState *s = bs->opaque;
    char *pbs_error = NULL;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    s->repository = g_strdup(qemu_opt_get(opts, PBS_OPT_REPOSITORY));
    s->snapshot = g_strdup(qemu_opt_get(opts, PBS_OPT_SNAPSHOT));
    s->archive = g_strdup(qemu_opt_get(opts, PBS_OPT_ARCHIVE));
    const char *keyfile = qemu_opt_get(opts, PBS_OPT_KEYFILE);
    const char *password = qemu_opt_get(opts, PBS_OPT_PASSWORD);
    const char *fingerprint = qemu_opt_get(opts, PBS_OPT_FINGERPRINT);
    const char *key_password = qemu_opt_get(opts, PBS_OPT_ENCRYPTION_PASSWORD);

    if (!password) {
        password = getenv("PBS_PASSWORD");
    }
    if (!fingerprint) {
        fingerprint = getenv("PBS_FINGERPRINT");
    }
    if (!key_password) {
        key_password = getenv("PBS_ENCRYPTION_PASSWORD");
    }

    /* connect to PBS server in read mode */
    s->conn = proxmox_restore_new(s->repository, s->snapshot, password,
        keyfile, key_password, fingerprint, &pbs_error);

    /* invalidates qemu_opt_get char pointers from above */
    qemu_opts_del(opts);

    if (!s->conn) {
        if (pbs_error && errp) error_setg(errp, "PBS restore_new failed: %s", pbs_error);
        if (pbs_error) proxmox_backup_free_error(pbs_error);
        return -ENOMEM;
    }

    int ret = proxmox_restore_connect(s->conn, &pbs_error);
    if (ret < 0) {
        if (pbs_error && errp) error_setg(errp, "PBS connect failed: %s", pbs_error);
        if (pbs_error) proxmox_backup_free_error(pbs_error);
        return -ECONNREFUSED;
    }

    /* acquire handle and length */
    s->aid = proxmox_restore_open_image(s->conn, s->archive, &pbs_error);
    if (s->aid < 0) {
        if (pbs_error && errp) error_setg(errp, "PBS open_image failed: %s", pbs_error);
        if (pbs_error) proxmox_backup_free_error(pbs_error);
        return -ENODEV;
    }
    s->length = proxmox_restore_get_image_length(s->conn, s->aid, &pbs_error);
    if (s->length < 0) {
        if (pbs_error && errp) error_setg(errp, "PBS get_image_length failed: %s", pbs_error);
        if (pbs_error) proxmox_backup_free_error(pbs_error);
        return -EINVAL;
    }

    return 0;
}

static int pbs_file_open(BlockDriverState *bs, QDict *options, int flags,
                         Error **errp)
{
    return pbs_open(bs, options, flags, errp);
}

static void pbs_close(BlockDriverState *bs) {
    BDRVPBSState *s = bs->opaque;
    g_free(s->repository);
    g_free(s->snapshot);
    g_free(s->archive);
    proxmox_restore_disconnect(s->conn);
}

static int64_t pbs_getlength(BlockDriverState *bs)
{
    BDRVPBSState *s = bs->opaque;
    return s->length;
}

typedef struct ReadCallbackData {
    Coroutine *co;
    AioContext *ctx;
} ReadCallbackData;

static void read_callback(void *callback_data)
{
    ReadCallbackData *rcb = callback_data;
    aio_co_schedule(rcb->ctx, rcb->co);
}

static coroutine_fn int pbs_co_preadv(BlockDriverState *bs,
                                      uint64_t offset, uint64_t bytes,
                                      QEMUIOVector *qiov, int flags)
{
    BDRVPBSState *s = bs->opaque;
    int ret;
    char *pbs_error = NULL;
    uint8_t *buf = malloc(bytes);

    ReadCallbackData rcb = {
        .co = qemu_coroutine_self(),
        .ctx = qemu_get_current_aio_context(),
    };

    proxmox_restore_read_image_at_async(s->conn, s->aid, buf, offset, bytes,
                                        read_callback, (void *) &rcb, &ret, &pbs_error);

    qemu_coroutine_yield();

    if (ret < 0) {
        fprintf(stderr, "error during PBS read: %s\n", pbs_error ? pbs_error : "unknown error");
        if (pbs_error) proxmox_backup_free_error(pbs_error);
        return -EIO;
    }

    qemu_iovec_from_buf(qiov, 0, buf, bytes);
    free(buf);

    return ret;
}

static coroutine_fn int pbs_co_pwritev(BlockDriverState *bs,
                                       uint64_t offset, uint64_t bytes,
                                       QEMUIOVector *qiov, int flags)
{
    fprintf(stderr, "pbs-bdrv: cannot write to backup file, make sure "
           "any attached disk devices are set to read-only!\n");
    return -EPERM;
}

static void pbs_refresh_filename(BlockDriverState *bs)
{
    BDRVPBSState *s = bs->opaque;
    snprintf(bs->exact_filename, sizeof(bs->exact_filename), "%s/%s(%s)",
             s->repository, s->snapshot, s->archive);
}

static const char *const pbs_strong_runtime_opts[] = {
    NULL
};

static BlockDriver bdrv_pbs_co = {
    .format_name            = "pbs",
    .protocol_name          = "pbs",
    .instance_size          = sizeof(BDRVPBSState),

    .bdrv_parse_filename    = pbs_parse_filename,

    .bdrv_file_open         = pbs_file_open,
    .bdrv_open              = pbs_open,
    .bdrv_close             = pbs_close,
    .bdrv_getlength         = pbs_getlength,

    .bdrv_co_preadv         = pbs_co_preadv,
    .bdrv_co_pwritev        = pbs_co_pwritev,

    .bdrv_refresh_filename  = pbs_refresh_filename,
    .strong_runtime_opts    = pbs_strong_runtime_opts,
};

static void bdrv_pbs_init(void)
{
    bdrv_register(&bdrv_pbs_co);
}

block_init(bdrv_pbs_init);
