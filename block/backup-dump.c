/*
 * BlockDriver to send backup data stream to a callback function
 *
 * Copyright (C) 2020 Proxmox Server Solutions GmbH
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/object_interfaces.h"
#include "block/block_int.h"

typedef struct {
    int             dump_cb_block_size;
    uint64_t        byte_size;
    BackupDumpFunc *dump_cb;
    void           *dump_cb_data;
} BDRVBackupDumpState;

static int qemu_backup_dump_get_info(BlockDriverState *bs, BlockDriverInfo *bdi)
{
    BDRVBackupDumpState *s = bs->opaque;

    bdi->cluster_size = s->dump_cb_block_size;
    bdi->unallocated_blocks_are_zero = true;
    return 0;
}

static int qemu_backup_dump_check_perm(
    BlockDriverState *bs,
    uint64_t perm,
    uint64_t shared,
    Error **errp)
{
    /* Nothing to do. */
    return 0;
}

static void qemu_backup_dump_set_perm(
    BlockDriverState *bs,
    uint64_t perm,
    uint64_t shared)
{
    /* Nothing to do. */
}

static void qemu_backup_dump_abort_perm_update(BlockDriverState *bs)
{
    /* Nothing to do. */
}

static void qemu_backup_dump_refresh_limits(BlockDriverState *bs, Error **errp)
{
    bs->bl.request_alignment = BDRV_SECTOR_SIZE; /* No sub-sector I/O */
}

static void qemu_backup_dump_close(BlockDriverState *bs)
{
    /* Nothing to do. */
}

static int64_t qemu_backup_dump_getlength(BlockDriverState *bs)
{
    BDRVBackupDumpState *s = bs->opaque;

    return s->byte_size;
}

static coroutine_fn int qemu_backup_dump_co_writev(
    BlockDriverState *bs,
    int64_t sector_num,
    int nb_sectors,
    QEMUIOVector *qiov,
    int flags)
{
    /* flags can be only values we set in supported_write_flags */
    assert(flags == 0);

    BDRVBackupDumpState *s = bs->opaque;
    off_t offset = sector_num * BDRV_SECTOR_SIZE;

    uint64_t written = 0;

    for (int i = 0; i < qiov->niov; ++i) {
        const struct iovec *v = &qiov->iov[i];

        int rc = s->dump_cb(s->dump_cb_data, offset, v->iov_len, v->iov_base);
        if (rc < 0) {
            return rc;
        }

        if (rc != v->iov_len) {
            return -EIO;
        }

        written += v->iov_len;
        offset += v->iov_len;
    }

    return written;
}

static void qemu_backup_dump_child_perm(
    BlockDriverState *bs,
    BdrvChild *c,
    const BdrvChildRole *role,
    BlockReopenQueue *reopen_queue,
    uint64_t perm, uint64_t shared,
    uint64_t *nperm, uint64_t *nshared)
{
    *nperm = BLK_PERM_ALL;
    *nshared = BLK_PERM_ALL;
}

static BlockDriver bdrv_backup_dump_drive = {
    .format_name                  = "backup-dump-drive",
    .protocol_name                = "backup-dump",
    .instance_size                = sizeof(BDRVBackupDumpState),

    .bdrv_close                   = qemu_backup_dump_close,
    .bdrv_has_zero_init           = bdrv_has_zero_init_1,
    .bdrv_getlength               = qemu_backup_dump_getlength,
    .bdrv_get_info                = qemu_backup_dump_get_info,

    .bdrv_co_writev               = qemu_backup_dump_co_writev,

    .bdrv_refresh_limits          = qemu_backup_dump_refresh_limits,
    .bdrv_check_perm              = qemu_backup_dump_check_perm,
    .bdrv_set_perm                = qemu_backup_dump_set_perm,
    .bdrv_abort_perm_update       = qemu_backup_dump_abort_perm_update,
    .bdrv_child_perm              = qemu_backup_dump_child_perm,
};

static void bdrv_backup_dump_init(void)
{
    bdrv_register(&bdrv_backup_dump_drive);
}

block_init(bdrv_backup_dump_init);


BlockDriverState *bdrv_backup_dump_create(
    int dump_cb_block_size,
    uint64_t byte_size,
    BackupDumpFunc *dump_cb,
    void *dump_cb_data,
    Error **errp)
{
    BDRVBackupDumpState *state;
    BlockDriverState *bs = bdrv_new_open_driver(
        &bdrv_backup_dump_drive, NULL, BDRV_O_RDWR, errp);

    if (!bs) {
        return NULL;
    }

    bs->total_sectors = byte_size / BDRV_SECTOR_SIZE;
    bs->opaque = state = g_new0(BDRVBackupDumpState, 1);

    state->dump_cb_block_size = dump_cb_block_size;
    state->byte_size = byte_size;
    state->dump_cb = dump_cb;
    state->dump_cb_data = dump_cb_data;

    return bs;
}
