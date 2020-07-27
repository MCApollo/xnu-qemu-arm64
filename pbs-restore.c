/*
 * Qemu image restore helper for Proxmox Backup
 *
 * Copyright (C) 2019 Proxmox Server Solutions
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
#include <getopt.h>
#include <string.h>

#include "qemu-common.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "sysemu/block-backend.h"

#include <proxmox-backup-qemu.h>

static void help(void)
{
    const char *help_msg =
        "usage: pbs-restore [--repository <repo>] snapshot archive-name target [command options]\n"
        ;

    printf("%s", help_msg);
    exit(1);
}

typedef struct CallbackData {
    BlockBackend *target;
    uint64_t last_offset;
    bool skip_zero;
} CallbackData;

static int write_callback(
    void *callback_data_ptr,
    uint64_t offset,
    const unsigned char *data,
    uint64_t data_len)
{
    int res = -1;

    CallbackData *callback_data = (CallbackData *)callback_data_ptr;

    uint64_t last_offset = callback_data->last_offset;
    if (offset > last_offset) callback_data->last_offset = offset;

    if (data == NULL) {
        if (callback_data->skip_zero && offset > last_offset) {
            return 0;
        }
        res = blk_pwrite_zeroes(callback_data->target, offset, data_len, 0);
    } else {
        res = blk_pwrite(callback_data->target, offset, data, data_len, 0);
    }

    if (res < 0) {
        fprintf(stderr, "blk_pwrite failed at offset %ld length %ld (%d) - %s\n", offset, data_len, res, strerror(-res));
        return res;
    }

    return 0;
}

int main(int argc, char **argv)
{
    Error *main_loop_err = NULL;
    const char *format = "raw";
    const char *repository = NULL;
    const char *keyfile = NULL;
    int verbose = false;
    bool skip_zero = false;

    error_init(argv[0]);

    for (;;) {
        static const struct option long_options[] = {
            {"help", no_argument, 0, 'h'},
            {"skip-zero", no_argument, 0, 'S'},
            {"verbose", no_argument, 0, 'v'},
            {"format", required_argument, 0, 'f'},
            {"repository", required_argument, 0, 'r'},
            {"keyfile", required_argument, 0, 'k'},
            {0, 0, 0, 0}
        };
        int c = getopt_long(argc, argv, "hvf:r:k:", long_options, NULL);
        if (c == -1) {
            break;
        }
        switch (c) {
            case ':':
                fprintf(stderr, "missing argument for option '%s'\n", argv[optind - 1]);
                return -1;
            case '?':
                fprintf(stderr, "unrecognized option '%s'\n", argv[optind - 1]);
                return -1;
            case 'f':
                format = g_strdup(argv[optind - 1]);
                break;
            case 'r':
                repository = g_strdup(argv[optind - 1]);
                break;
            case 'k':
                keyfile = g_strdup(argv[optind - 1]);
                break;
            case 'v':
                verbose = true;
                break;
            case 'S':
                skip_zero = true;
                break;
            case 'h':
                help();
                return 0;
        }
    }

    if (optind >= argc - 2) {
        fprintf(stderr, "missing arguments\n");
        help();
        return -1;
    }

    if (repository == NULL) {
        repository = getenv("PBS_REPOSITORY");
    }

    if (repository == NULL) {
        fprintf(stderr, "no repository specified\n");
        help();
        return -1;
    }

    char *snapshot = argv[optind++];
    char *archive_name = argv[optind++];
    char *target = argv[optind++];

    const char *password = getenv("PBS_PASSWORD");
    const char *fingerprint = getenv("PBS_FINGERPRINT");
    const char *key_password = getenv("PBS_ENCRYPTION_PASSWORD");

    if (qemu_init_main_loop(&main_loop_err)) {
        g_error("%s", error_get_pretty(main_loop_err));
    }

    bdrv_init();
    module_call_init(MODULE_INIT_QOM);

    if (verbose) {
        fprintf(stderr, "connecting to repository '%s'\n", repository);
    }
    char *pbs_error = NULL;
    ProxmoxRestoreHandle *conn = proxmox_restore_new(
        repository, snapshot, password, keyfile, key_password, fingerprint, &pbs_error);
    if (conn == NULL) {
        fprintf(stderr, "restore failed: %s\n", pbs_error);
        return -1;
    }

    int res = proxmox_restore_connect(conn, &pbs_error);
    if (res < 0 || pbs_error) {
        fprintf(stderr, "restore failed (connection error): %s\n", pbs_error);
        return -1;
    }

    QDict *options = qdict_new();

    if (format) {
        qdict_put_str(options, "driver", format);
    }


    if (verbose) {
        fprintf(stderr, "open block backend for target '%s'\n", target);
    }
    Error *local_err = NULL;
    int flags = BDRV_O_RDWR;
    BlockBackend *blk = blk_new_open(target, NULL, options, flags, &local_err);
    if (!blk) {
        fprintf(stderr, "%s\n", error_get_pretty(local_err));
        return -1;
    }

    CallbackData *callback_data = calloc(sizeof(CallbackData), 1);

    callback_data->target = blk;
    callback_data->skip_zero = skip_zero;
    callback_data->last_offset = 0;

    // blk_set_enable_write_cache(blk, !writethrough);

    if (verbose) {
        fprintf(stderr, "starting to restore snapshot '%s'\n", snapshot);
        fflush(stderr); // ensure we do not get printed after the progress log
    }
    res = proxmox_restore_image(
        conn,
        archive_name,
        write_callback,
        callback_data,
        &pbs_error,
        verbose);

    proxmox_restore_disconnect(conn);

    if (res < 0) {
        fprintf(stderr, "restore failed: %s\n", pbs_error);
        return -1;
    }

    return 0;
}
