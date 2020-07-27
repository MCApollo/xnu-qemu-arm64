#ifndef PROXMOX_BACKUP_CLIENT_H
#define PROXMOX_BACKUP_CLIENT_H

#include "qemu/osdep.h"
#include "qemu/coroutine.h"
#include "proxmox-backup-qemu.h"

void block_on_coroutine_fn(CoroutineEntry *entry, void *entry_arg);

int coroutine_fn
proxmox_backup_co_connect(
    ProxmoxBackupHandle *pbs,
    Error **errp);

int coroutine_fn
proxmox_backup_co_add_config(
    ProxmoxBackupHandle *pbs,
    const char *name,
    const uint8_t *data,
    uint64_t size,
    Error **errp);

int coroutine_fn
proxmox_backup_co_register_image(
    ProxmoxBackupHandle *pbs,
    const char *device_name,
    uint64_t size,
    bool incremental,
    Error **errp);


int coroutine_fn
proxmox_backup_co_finish(
    ProxmoxBackupHandle *pbs,
    Error **errp);

int coroutine_fn
proxmox_backup_co_close_image(
    ProxmoxBackupHandle *pbs,
    uint8_t dev_id,
    Error **errp);

int coroutine_fn
proxmox_backup_co_write_data(
    ProxmoxBackupHandle *pbs,
    uint8_t dev_id,
    const uint8_t *data,
    uint64_t offset,
    uint64_t size,
    Error **errp);


#endif /* PROXMOX_BACKUP_CLIENT_H */
