//! Sweeping stale partial transfer directories (docs/04-protocol.md, DCR-154).

use tradr_core::{DirEntry, EntryKind, ItemId, RootId, TransferId, UnixTime, Vfs, VfsError};
use tradr_vfs::{partial_dir_rel_path, partial_file_rel_path};

/// Retention period in seconds for partial transfers before they are swept.
pub const PARTIAL_RETENTION_SECS: u64 = 604_800;

fn is_stale(now: UnixTime, modified: UnixTime) -> bool {
    if modified.as_secs() > now.as_secs() {
        return false;
    }
    now.as_secs().saturating_sub(modified.as_secs()) > PARTIAL_RETENTION_SECS as i64
}

/// Sweeps partial transfer directories untouched for longer than the retention period.
pub async fn sweep_stale_partials(
    vfs: &impl Vfs,
    root: RootId,
    now: UnixTime,
    partial_root: &[DirEntry],
) -> Result<Vec<TransferId>, VfsError> {
    let mut swept = Vec::new();

    for entry in partial_root {
        if entry.kind != EntryKind::Directory {
            continue;
        }

        let Ok(transfer_id) = entry.name.parse::<TransferId>() else {
            continue;
        };

        if transfer_id.to_string() != entry.name {
            continue;
        }

        if !is_stale(now, entry.modified) {
            continue;
        }

        let dir_rel = partial_dir_rel_path(transfer_id);
        let children = vfs.list(root, &dir_rel).await?;

        let mut items = Vec::new();
        let mut should_sweep = true;

        for child in &children {
            if child.kind != EntryKind::File {
                should_sweep = false;
                break;
            }

            let Ok(item_id) = ItemId::new(&child.name) else {
                should_sweep = false;
                break;
            };

            if item_id.to_string() != child.name {
                should_sweep = false;
                break;
            }

            if !is_stale(now, child.modified) {
                should_sweep = false;
                break;
            }

            items.push(item_id);
        }

        if !should_sweep {
            continue;
        }

        for item_id in items {
            let file_rel = partial_file_rel_path(transfer_id, &item_id);
            vfs.remove(root, &file_rel).await?;
        }

        vfs.remove(root, &dir_rel).await?;
        swept.push(transfer_id);
    }

    Ok(swept)
}
