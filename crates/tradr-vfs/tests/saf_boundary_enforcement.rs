//! Supervisor-authored tests for SAF VFS boundary enforcement.
//! Critical Module: Boundary enforcement in tradr-vfs.
//! See docs/04-protocol.md, docs/06-shares-and-linking.md, and AGENTS.md section 6.

use std::sync::Arc;

use std::future::Future;
use std::pin::Pin;
use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::{SafBridge, SafNode, SafVfs};
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

struct MockSafBridge {}

impl SafBridge for MockSafBridge {
    fn list_children<'a>(
        &'a self,
        _doc_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<SafNode>, VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn open_file<'a>(
        &'a self,
        _doc_id: &'a str,
        _mode: &'a str,
    ) -> BoxFuture<'a, Result<std::fs::File, VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn create_dir<'a>(
        &'a self,
        _parent_id: &'a str,
        _display_name: &'a str,
    ) -> BoxFuture<'a, Result<String, VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn create_file<'a>(
        &'a self,
        _parent_id: &'a str,
        _display_name: &'a str,
    ) -> BoxFuture<'a, Result<String, VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn rename<'a>(
        &'a self,
        _doc_id: &'a str,
        _new_name: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn remove<'a>(&'a self, _doc_id: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }
}

#[tokio::test]
async fn read_only_root_refuses_modifications() {
    let bridge = Arc::new(MockSafBridge {});
    let vfs = SafVfs::new(bridge);
    let root = RootId::new(2);
    vfs.register_root(
        root,
        "content://com.android.providers.document/tree/mock".to_string(),
        true,
    )
    .expect("register root");

    let rel = RelPath::new("file.txt").expect("relpath");
    assert_eq!(
        vfs.open_write(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.create_dir(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.rename(root, &rel, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.remove(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
}

#[tokio::test]
async fn partial_directory_is_inaccessible_to_peers() {
    let bridge = Arc::new(MockSafBridge {});
    let vfs = SafVfs::new(bridge);
    let root = RootId::new(2);
    vfs.register_root(root, "content://...".to_string(), false)
        .expect("register root");

    let rel = RelPath::new(".tradr-partial").expect("relpath");

    // Must be denied by boundary enforcement (deny list)
    assert_eq!(
        vfs.list(root, &rel).await.unwrap_err(),
        VfsError::DenyListed
    );
}
