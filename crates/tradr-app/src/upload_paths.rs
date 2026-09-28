//! Staging paths and name collision resolution for browse uploads.

use tradr_core::{BoxFuture, ItemId, RelPath, RootId, UploadPaths, Vfs, VfsError};
use tradr_identity::{OsRng, SystemClock};
use tradr_vfs::{partial_dir_rel_path, partial_file_rel_path, resolve_collision};

use crate::send::generate_transfer_id;

/// Resolves staging locations and filename collisions for browse uploads.
pub struct PartialUploadPaths;

impl UploadPaths for PartialUploadPaths {
    fn staging(&self) -> Result<(RelPath, RelPath), VfsError> {
        let transfer_id = generate_transfer_id(&OsRng, &SystemClock)
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        let item_id =
            ItemId::new("upload").map_err(|_| VfsError::Io(std::io::ErrorKind::InvalidInput))?;
        let dir = partial_dir_rel_path(transfer_id);
        let file = partial_file_rel_path(transfer_id, &item_id);
        Ok((dir, file))
    }

    fn free_name<'a>(
        &'a self,
        vfs: &'a dyn Vfs,
        root: RootId,
        wanted: &'a RelPath,
    ) -> BoxFuture<'a, Result<RelPath, VfsError>> {
        Box::pin(async move { resolve_collision(vfs, root, wanted).await })
    }
}
