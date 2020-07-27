/*
 * VMA: Virtual Machine Archive
 *
 * Copyright (C) 2012-2013 Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <glib.h>

#include "vma.h"
#include "qemu-common.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/cutils.h"
#include "qapi/qmp/qdict.h"
#include "sysemu/block-backend.h"

static void help(void)
{
    const char *help_msg =
        "usage: vma command [command options]\n"
        "\n"
        "vma list <filename>\n"
        "vma config <filename> [-c config]\n"
        "vma create <filename> [-c config] pathname ...\n"
        "vma extract <filename> [-r <fifo>] <targetdir>\n"
        "vma verify <filename> [-v]\n"
        ;

    printf("%s", help_msg);
    exit(1);
}

static const char *extract_devname(const char *path, char **devname, int index)
{
    assert(path);

    const char *sep = strchr(path, '=');

    if (sep) {
        *devname = g_strndup(path, sep - path);
        path = sep + 1;
    } else {
        if (index >= 0) {
            *devname = g_strdup_printf("disk%d", index);
        } else {
            *devname = NULL;
        }
    }

    return path;
}

static void print_content(VmaReader *vmar)
{
    assert(vmar);

    VmaHeader *head = vma_reader_get_header(vmar);

    GList *l = vma_reader_get_config_data(vmar);
    while (l && l->data) {
        VmaConfigData *cdata = (VmaConfigData *)l->data;
        l = g_list_next(l);
        printf("CFG: size: %d name: %s\n", cdata->len, cdata->name);
    }

    int i;
    VmaDeviceInfo *di;
    for (i = 1; i < 255; i++) {
        di = vma_reader_get_device_info(vmar, i);
        if (di) {
            if (strcmp(di->devname, "vmstate") == 0) {
                printf("VMSTATE: dev_id=%d memory: %zd\n", i, di->size);
            } else {
                printf("DEV: dev_id=%d size: %zd devname: %s\n",
                       i, di->size, di->devname);
            }
        }
    }
    /* ctime is the last entry we print */
    printf("CTIME: %s", ctime(&head->ctime));
    fflush(stdout);
}

static int list_content(int argc, char **argv)
{
    int c, ret = 0;
    const char *filename;

    for (;;) {
        c = getopt(argc, argv, "h");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        default:
            g_assert_not_reached();
        }
    }

    /* Get the filename */
    if ((optind + 1) != argc) {
        help();
    }
    filename = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    print_content(vmar);

    vma_reader_destroy(vmar);

    return ret;
}

typedef struct RestoreMap {
    char *devname;
    char *path;
    char *format;
    uint64_t throttling_bps;
    char *throttling_group;
    char *cache;
    bool write_zero;
} RestoreMap;

static bool try_parse_option(char **line, const char *optname, char **out, const char *inbuf) {
    size_t optlen = strlen(optname);
    if (strncmp(*line, optname, optlen) != 0 || (*line)[optlen] != '=') {
        return false;
    }
    if (*out) {
        g_error("read map failed - duplicate value for option '%s'", optname);
    }
    char *value = (*line) + optlen + 1; /* including a '=' */
    char *colon = strchr(value, ':');
    if (!colon) {
        g_error("read map failed - option '%s' not terminated ('%s')",
                optname, inbuf);
    }
    *line = colon+1;
    *out = g_strndup(value, colon - value);
    return true;
}

static uint64_t verify_u64(const char *text) {
    uint64_t value;
    const char *endptr = NULL;
    if (qemu_strtou64(text, &endptr, 0, &value) != 0 || !endptr || *endptr) {
        g_error("read map failed - not a number: %s", text);
    }
    return value;
}

static int extract_content(int argc, char **argv)
{
    int c, ret = 0;
    int verbose = 0;
    const char *filename;
    const char *dirname;
    const char *readmap = NULL;

    for (;;) {
        c = getopt(argc, argv, "hvr:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'r':
            readmap = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            help();
        }
    }

    /* Get the filename */
    if ((optind + 2) != argc) {
        help();
    }
    filename = argv[optind++];
    dirname = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    if (mkdir(dirname, 0777) < 0) {
        g_error("unable to create target directory %s - %s",
                dirname, g_strerror(errno));
    }

    GList *l = vma_reader_get_config_data(vmar);
    while (l && l->data) {
        VmaConfigData *cdata = (VmaConfigData *)l->data;
        l = g_list_next(l);
        char *cfgfn = g_strdup_printf("%s/%s", dirname, cdata->name);
        GError *err = NULL;
        if (!g_file_set_contents(cfgfn, (gchar *)cdata->data, cdata->len,
                                 &err)) {
            g_error("unable to write file: %s", err->message);
        }
    }

    GHashTable *devmap = g_hash_table_new(g_str_hash, g_str_equal);

    if (readmap) {
        print_content(vmar);

        FILE *map = fopen(readmap, "r");
        if (!map) {
            g_error("unable to open fifo %s - %s", readmap, g_strerror(errno));
        }

        while (1) {
            char inbuf[8192];
            char *line = fgets(inbuf, sizeof(inbuf), map);
            char *format = NULL;
            char *bps = NULL;
            char *group = NULL;
            char *cache = NULL;
            if (!line || line[0] == '\0' || !strcmp(line, "done\n")) {
                break;
            }
            int len = strlen(line);
            if (line[len - 1] == '\n') {
                line[len - 1] = '\0';
                if (len == 1) {
                    break;
                }
            }

            while (1) {
                if (!try_parse_option(&line, "format", &format, inbuf) &&
                    !try_parse_option(&line, "throttling.bps", &bps, inbuf) &&
                    !try_parse_option(&line, "throttling.group", &group, inbuf) &&
                    !try_parse_option(&line, "cache", &cache, inbuf))
                {
                    break;
                }
            }

            uint64_t bps_value = 0;
            if (bps) {
                bps_value = verify_u64(bps);
                g_free(bps);
            }

            const char *path;
            bool write_zero;
            if (line[0] == '0' && line[1] == ':') {
                path = line + 2;
                write_zero = false;
            } else if (line[0] == '1' && line[1] == ':') {
                path = line + 2;
                write_zero = true;
            } else {
                g_error("read map failed - parse error ('%s')", inbuf);
            }

            char *devname = NULL;
            path = extract_devname(path, &devname, -1);
            if (!devname) {
                g_error("read map failed - no dev name specified ('%s')",
                        inbuf);
            }

            RestoreMap *map = g_new0(RestoreMap, 1);
            map->devname = g_strdup(devname);
            map->path = g_strdup(path);
            map->format = format;
            map->throttling_bps = bps_value;
            map->throttling_group = group;
            map->cache = cache;
            map->write_zero = write_zero;

            g_hash_table_insert(devmap, map->devname, map);

        };
    }

    int i;
    int vmstate_fd = -1;
    guint8 vmstate_stream = 0;

    BlockBackend *blk = NULL;

    for (i = 1; i < 255; i++) {
        VmaDeviceInfo *di = vma_reader_get_device_info(vmar, i);
        if (di && (strcmp(di->devname, "vmstate") == 0)) {
            vmstate_stream = i;
            char *statefn = g_strdup_printf("%s/vmstate.bin", dirname);
            vmstate_fd = open(statefn, O_WRONLY|O_CREAT|O_EXCL, 0644);
            if (vmstate_fd < 0) {
                g_error("create vmstate file '%s' failed - %s", statefn,
                        g_strerror(errno));
            }
            g_free(statefn);
        } else if (di) {
            char *devfn = NULL;
            const char *format = NULL;
            uint64_t throttling_bps = 0;
            const char *throttling_group = NULL;
            const char *cache = NULL;
            int flags = BDRV_O_RDWR;
            bool write_zero = true;

            if (readmap) {
                RestoreMap *map;
                map = (RestoreMap *)g_hash_table_lookup(devmap, di->devname);
                if (map == NULL) {
                    g_error("no device name mapping for %s", di->devname);
                }
                devfn = map->path;
                format = map->format;
                throttling_bps = map->throttling_bps;
                throttling_group = map->throttling_group;
                cache = map->cache;
                write_zero = map->write_zero;
            } else {
                devfn = g_strdup_printf("%s/tmp-disk-%s.raw",
                                        dirname, di->devname);
                printf("DEVINFO %s %zd\n", devfn, di->size);

                bdrv_img_create(devfn, "raw", NULL, NULL, NULL, di->size,
                                flags, true, &errp);
                if (errp) {
                    g_error("can't create file %s: %s", devfn,
                            error_get_pretty(errp));
                }

                /* Note: we created an empty file above, so there is no
                 * need to write zeroes (so we generate a sparse file)
                 */
                write_zero = false;
            }

	    size_t devlen = strlen(devfn);
	    QDict *options = NULL;
            bool writethrough;
            if (format) {
                /* explicit format from commandline */
                options = qdict_new();
                qdict_put_str(options, "driver", format);
            } else if ((devlen > 4 && strcmp(devfn+devlen-4, ".raw") == 0) ||
	               strncmp(devfn, "/dev/", 5) == 0)
	    {
                /* This part is now deprecated for PVE as well (just as qemu
                 * deprecated not specifying an explicit raw format, too.
                 */
		/* explicit raw format */
		options = qdict_new();
		qdict_put_str(options, "driver", "raw");
	    }
            if (cache && bdrv_parse_cache_mode(cache, &flags, &writethrough)) {
                g_error("invalid cache option: %s\n", cache);
            }

	    if (errp || !(blk = blk_new_open(devfn, NULL, options, flags, &errp))) {
                g_error("can't open file %s - %s", devfn,
                        error_get_pretty(errp));
            }

            if (cache) {
                blk_set_enable_write_cache(blk, !writethrough);
            }

            if (throttling_group) {
                blk_io_limits_enable(blk, throttling_group);
            }

            if (throttling_bps) {
                if (!throttling_group) {
                    blk_io_limits_enable(blk, devfn);
                }

                ThrottleConfig cfg;
                throttle_config_init(&cfg);
                cfg.buckets[THROTTLE_BPS_WRITE].avg = throttling_bps;
                Error *err = NULL;
                if (!throttle_is_valid(&cfg, &err)) {
                    error_report_err(err);
                    g_error("failed to apply throttling");
                }
                blk_set_io_limits(blk, &cfg);
            }

            if (vma_reader_register_bs(vmar, i, blk, write_zero, &errp) < 0) {
                g_error("%s", error_get_pretty(errp));
            }

            if (!readmap) {
                g_free(devfn);
            }
        }
    }

    if (vma_reader_restore(vmar, vmstate_fd, verbose, &errp) < 0) {
        g_error("restore failed - %s", error_get_pretty(errp));
    }

    if (!readmap) {
        for (i = 1; i < 255; i++) {
            VmaDeviceInfo *di = vma_reader_get_device_info(vmar, i);
            if (di && (i != vmstate_stream)) {
                char *tmpfn = g_strdup_printf("%s/tmp-disk-%s.raw",
                                              dirname, di->devname);
                char *fn = g_strdup_printf("%s/disk-%s.raw",
                                           dirname, di->devname);
                if (rename(tmpfn, fn) != 0) {
                    g_error("rename %s to %s failed - %s",
                            tmpfn, fn, g_strerror(errno));
                }
            }
        }
    }

    vma_reader_destroy(vmar);

    blk_unref(blk);

    bdrv_close_all();

    return ret;
}

static int verify_content(int argc, char **argv)
{
    int c, ret = 0;
    int verbose = 0;
    const char *filename;

    for (;;) {
        c = getopt(argc, argv, "hv");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            help();
        }
    }

    /* Get the filename */
    if ((optind + 1) != argc) {
        help();
    }
    filename = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    if (verbose) {
        print_content(vmar);
    }

    if (vma_reader_verify(vmar, verbose, &errp) < 0) {
        g_error("verify failed - %s", error_get_pretty(errp));
    }

    vma_reader_destroy(vmar);

    bdrv_close_all();

    return ret;
}

typedef struct BackupJob {
    BlockBackend *target;
    int64_t len;
    VmaWriter *vmaw;
    uint8_t dev_id;
} BackupJob;

#define BACKUP_SECTORS_PER_CLUSTER (VMA_CLUSTER_SIZE / BDRV_SECTOR_SIZE)

static void coroutine_fn backup_run_empty(void *opaque)
{
    VmaWriter *vmaw = (VmaWriter *)opaque;

    vma_writer_flush_output(vmaw);

    Error *err = NULL;
    if (vma_writer_close(vmaw, &err) != 0) {
        g_warning("vma_writer_close failed %s", error_get_pretty(err));
    }
}

static void coroutine_fn backup_run(void *opaque)
{
    BackupJob *job = (BackupJob *)opaque;
    struct iovec iov;
    QEMUIOVector qiov;

    int64_t start, end;
    int ret = 0;

    unsigned char *buf = blk_blockalign(job->target, VMA_CLUSTER_SIZE);

    start = 0;
    end = DIV_ROUND_UP(job->len / BDRV_SECTOR_SIZE,
                       BACKUP_SECTORS_PER_CLUSTER);

    for (; start < end; start++) {
        iov.iov_base = buf;
        iov.iov_len = VMA_CLUSTER_SIZE;
        qemu_iovec_init_external(&qiov, &iov, 1);

        ret = blk_co_preadv(job->target, start * VMA_CLUSTER_SIZE,
                            VMA_CLUSTER_SIZE, &qiov, 0);
        if (ret < 0) {
            vma_writer_set_error(job->vmaw, "read error", -1);
            goto out;
        }

        size_t zb = 0;
        if (vma_writer_write(job->vmaw, job->dev_id, start, buf, &zb) < 0) {
            vma_writer_set_error(job->vmaw, "backup_dump_cb vma_writer_write failed", -1);
            goto out;
        }
    }


out:
    if (vma_writer_close_stream(job->vmaw, job->dev_id) <= 0) {
        Error *err = NULL;
        if (vma_writer_close(job->vmaw, &err) != 0) {
            g_warning("vma_writer_close failed %s", error_get_pretty(err));
        }
    }
    qemu_vfree(buf);
}

static int create_archive(int argc, char **argv)
{
    int i, c;
    int verbose = 0;
    const char *archivename;
    GList *config_files = NULL;

    for (;;) {
        c = getopt(argc, argv, "hvc:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'c':
            config_files = g_list_append(config_files, optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            g_assert_not_reached();
        }
    }


    /* make sure we an archive name */
    if ((optind + 1) > argc) {
        help();
    }

    archivename = argv[optind++];

    uuid_t uuid;
    uuid_generate(uuid);

    Error *local_err = NULL;
    VmaWriter *vmaw = vma_writer_create(archivename, uuid, &local_err);

    if (vmaw == NULL) {
        g_error("%s", error_get_pretty(local_err));
    }

    GList *l = config_files;
    while (l && l->data) {
        char *name = l->data;
        char *cdata = NULL;
        gsize clen = 0;
        GError *err = NULL;
        if (!g_file_get_contents(name, &cdata, &clen, &err)) {
            unlink(archivename);
            g_error("Unable to read file: %s", err->message);
        }

        if (vma_writer_add_config(vmaw, name, cdata, clen) != 0) {
            unlink(archivename);
            g_error("Unable to append config data %s (len = %zd)",
                    name, clen);
        }
        l = g_list_next(l);
    }

    int devcount = 0;
    while (optind < argc) {
        const char *path = argv[optind++];
        char *devname = NULL;
        path = extract_devname(path, &devname, devcount++);

        Error *errp = NULL;
        BlockBackend *target;

        target = blk_new_open(path, NULL, NULL, 0, &errp);
        if (!target) {
            unlink(archivename);
            g_error("bdrv_open '%s' failed - %s", path, error_get_pretty(errp));
        }
        int64_t size = blk_getlength(target);
        int dev_id = vma_writer_register_stream(vmaw, devname, size);
        if (dev_id <= 0) {
            unlink(archivename);
            g_error("vma_writer_register_stream '%s' failed", devname);
        }

        BackupJob *job = g_new0(BackupJob, 1);
        job->len = size;
        job->target = target;
        job->vmaw = vmaw;
        job->dev_id = dev_id;

        Coroutine *co = qemu_coroutine_create(backup_run, job);
        qemu_coroutine_enter(co);
    }

    VmaStatus vmastat;
    int percent = 0;
    int last_percent = -1;

    if (devcount) {
        while (1) {
            main_loop_wait(false);
            vma_writer_get_status(vmaw, &vmastat);

            if (verbose) {

                uint64_t total = 0;
                uint64_t transferred = 0;
                uint64_t zero_bytes = 0;

                int i;
                for (i = 0; i < 256; i++) {
                    if (vmastat.stream_info[i].size) {
                        total += vmastat.stream_info[i].size;
                        transferred += vmastat.stream_info[i].transferred;
                        zero_bytes += vmastat.stream_info[i].zero_bytes;
                    }
                }
                percent = (transferred*100)/total;
                if (percent != last_percent) {
                    fprintf(stderr, "progress %d%% %zd/%zd %zd\n", percent,
                            transferred, total, zero_bytes);
                    fflush(stderr);

                    last_percent = percent;
                }
            }

            if (vmastat.closed) {
                break;
            }
        }
    } else {
        Coroutine *co = qemu_coroutine_create(backup_run_empty, vmaw);
        qemu_coroutine_enter(co);
        while (1) {
            main_loop_wait(false);
            vma_writer_get_status(vmaw, &vmastat);
            if (vmastat.closed) {
                    break;
            }
        }
    }

    bdrv_drain_all();

    vma_writer_get_status(vmaw, &vmastat);

    if (verbose) {
        for (i = 0; i < 256; i++) {
            VmaStreamInfo *si = &vmastat.stream_info[i];
            if (si->size) {
                fprintf(stderr, "image %s: size=%zd zeros=%zd saved=%zd\n",
                        si->devname, si->size, si->zero_bytes,
                        si->size - si->zero_bytes);
            }
        }
    }

    if (vmastat.status < 0) {
        unlink(archivename);
        g_error("creating vma archive failed");
    }

    vma_writer_destroy(vmaw);
    return 0;
}

static int dump_config(int argc, char **argv)
{
    int c, ret = 0;
    const char *filename;
    const char *config_name = "qemu-server.conf";

    for (;;) {
        c = getopt(argc, argv, "hc:");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'c':
            config_name = optarg;
            break;
        default:
            help();
        }
    }

    /* Get the filename */
    if ((optind + 1) != argc) {
        help();
    }
    filename = argv[optind++];

    Error *errp = NULL;
    VmaReader *vmar = vma_reader_create(filename, &errp);

    if (!vmar) {
        g_error("%s", error_get_pretty(errp));
    }

    int found = 0;
    GList *l = vma_reader_get_config_data(vmar);
    while (l && l->data) {
        VmaConfigData *cdata = (VmaConfigData *)l->data;
        l = g_list_next(l);
        if (strcmp(cdata->name, config_name) == 0) {
            found = 1;
            fwrite(cdata->data,  cdata->len, 1, stdout);
            break;
        }
    }

    vma_reader_destroy(vmar);

    bdrv_close_all();

    if (!found) {
        fprintf(stderr, "unable to find configuration data '%s'\n", config_name);
        return -1;
    }

    return ret;
}

int main(int argc, char **argv)
{
    const char *cmdname;
    Error *main_loop_err = NULL;

    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_exec_dir(argv[0]);

    if (qemu_init_main_loop(&main_loop_err)) {
        g_error("%s", error_get_pretty(main_loop_err));
    }

    bdrv_init();
    module_call_init(MODULE_INIT_QOM);

    if (argc < 2) {
        help();
    }

    cmdname = argv[1];
    argc--; argv++;


    if (!strcmp(cmdname, "list")) {
        return list_content(argc, argv);
    } else if (!strcmp(cmdname, "create")) {
        return create_archive(argc, argv);
    } else if (!strcmp(cmdname, "extract")) {
        return extract_content(argc, argv);
    } else if (!strcmp(cmdname, "verify")) {
        return verify_content(argc, argv);
    } else if (!strcmp(cmdname, "config")) {
        return dump_config(argc, argv);
    }

    help();
    return 0;
}
