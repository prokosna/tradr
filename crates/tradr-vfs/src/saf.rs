use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

use crate::sanitization::{check_deny_list, check_deny_list_write, is_denied};
use crate::{PosixReadHandle, PosixWriteHandle};

/// A node reported by the SAF bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafNode {
    pub doc_id: String,
    pub display_name: String,
    pub kind: EntryKind,
    pub size_bytes: u64,
    pub modified: UnixTime,
}

/// The bridge to Kotlin SAF API.
pub trait SafBridge: Send + Sync {
    /// Lists the children of a given document ID.
    fn list_children<'a>(
        &'a self,
        doc_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<SafNode>, VfsError>>;

    /// Opens a file descriptor for a document.
    fn open_file<'a>(
        &'a self,
        doc_id: &'a str,
        mode: &'a str,
    ) -> BoxFuture<'a, Result<std::fs::File, VfsError>>;

    /// Creates a directory.
    fn create_dir<'a>(
        &'a self,
        parent_id: &'a str,
        display_name: &'a str,
    ) -> BoxFuture<'a, Result<String, VfsError>>;

    /// Creates a file.
    fn create_file<'a>(
        &'a self,
        parent_id: &'a str,
        display_name: &'a str,
    ) -> BoxFuture<'a, Result<String, VfsError>>;

    /// Renames a document.
    fn rename<'a>(
        &'a self,
        doc_id: &'a str,
        new_name: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Removes a document.
    fn remove<'a>(&'a self, doc_id: &'a str) -> BoxFuture<'a, Result<(), VfsError>>;
}

#[derive(Debug, Clone)]
struct SafRootEntry {
    root_doc_id: String,
    read_only: bool,
}

/// Storage Access Framework filesystem backend for Android.
pub struct SafVfs {
    bridge: Arc<dyn SafBridge>,
    roots: RwLock<HashMap<u64, SafRootEntry>>,
}

impl SafVfs {
    /// Creates a new `SafVfs` backed by the given `SafBridge`.
    pub fn new(bridge: Arc<dyn SafBridge>) -> Self {
        Self {
            bridge,
            roots: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a SAF document tree root for a given `RootId`.
    pub fn register_root(
        &self,
        root: RootId,
        root_doc_id: String,
        read_only: bool,
    ) -> Result<(), VfsError> {
        let mut roots = self
            .roots
            .write()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.insert(
            root.value(),
            SafRootEntry {
                root_doc_id,
                read_only,
            },
        );
        Ok(())
    }

    fn get_root(&self, root: RootId) -> Result<SafRootEntry, VfsError> {
        let roots = self
            .roots
            .read()
            .map_err(|_| VfsError::Io(std::io::ErrorKind::Other))?;
        roots.get(&root.value()).cloned().ok_or(VfsError::NotFound)
    }

    async fn resolve_node(
        &self,
        root_doc_id: &str,
        components: &[&str],
    ) -> Result<SafNode, VfsError> {
        if components.is_empty() {
            return Ok(SafNode {
                doc_id: root_doc_id.to_string(),
                display_name: String::new(),
                kind: EntryKind::Directory,
                size_bytes: 0,
                modified: UnixTime::from_secs(0),
            });
        }

        let mut cur_id = root_doc_id.to_string();
        for (i, comp) in components.iter().enumerate() {
            let children = self.bridge.list_children(&cur_id).await?;
            let node = children
                .into_iter()
                .find(|n| n.display_name == *comp)
                .ok_or(VfsError::NotFound)?;

            if i + 1 < components.len() {
                if node.kind != EntryKind::Directory {
                    return Err(VfsError::WrongKind);
                }
                cur_id = node.doc_id;
            } else {
                return Ok(node);
            }
        }

        Err(VfsError::NotFound)
    }

    async fn create_dir_internal(&self, root_doc_id: &str, at: &RelPath) -> Result<(), VfsError> {
        if at.as_str().is_empty() {
            return Ok(());
        }
        let components: Vec<&str> = at.components().collect();
        let mut cur_id = root_doc_id.to_string();
        for comp in components {
            let children = self.bridge.list_children(&cur_id).await?;
            if let Some(existing) = children.into_iter().find(|n| n.display_name == comp) {
                if existing.kind != EntryKind::Directory {
                    return Err(VfsError::WrongKind);
                }
                cur_id = existing.doc_id;
            } else {
                let created_id = self.bridge.create_dir(&cur_id, comp).await?;
                cur_id = created_id;
            }
        }
        Ok(())
    }
}

impl Vfs for SafVfs {
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            check_deny_list(&at)?;
            let root_entry = self.get_root(root)?;
            let components: Vec<&str> = at.components().collect();
            let target_doc_id = if components.is_empty() {
                root_entry.root_doc_id.clone()
            } else {
                let node = self
                    .resolve_node(&root_entry.root_doc_id, &components)
                    .await?;
                if node.kind != EntryKind::Directory {
                    return Err(VfsError::WrongKind);
                }
                node.doc_id
            };

            let children = self.bridge.list_children(&target_doc_id).await?;
            let mut entries = Vec::new();
            for child in children {
                let mut child_components = components.clone();
                child_components.push(&child.display_name);
                if is_denied(&child_components) {
                    continue;
                }
                let size_bytes = if child.kind == EntryKind::Directory {
                    0
                } else {
                    child.size_bytes
                };
                entries.push(DirEntry {
                    name: child.display_name,
                    kind: child.kind,
                    size_bytes,
                    modified: child.modified,
                });
            }
            Ok(entries)
        })
    }

    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            check_deny_list(&at)?;
            let root_entry = self.get_root(root)?;
            let components: Vec<&str> = at.components().collect();
            if components.is_empty() {
                Ok(Metadata {
                    kind: EntryKind::Directory,
                    size_bytes: 0,
                    modified: UnixTime::from_secs(0),
                })
            } else {
                let node = self
                    .resolve_node(&root_entry.root_doc_id, &components)
                    .await?;
                let size_bytes = if node.kind == EntryKind::Directory {
                    0
                } else {
                    node.size_bytes
                };
                Ok(Metadata {
                    kind: node.kind,
                    size_bytes,
                    modified: node.modified,
                })
            }
        })
    }

    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            check_deny_list(&at)?;
            if at.as_str().is_empty() {
                return Err(VfsError::WrongKind);
            }
            let root_entry = self.get_root(root)?;
            let components: Vec<&str> = at.components().collect();
            let node = self
                .resolve_node(&root_entry.root_doc_id, &components)
                .await?;
            if node.kind != EntryKind::File {
                return Err(VfsError::WrongKind);
            }
            let file = self.bridge.open_file(&node.doc_id, "r").await?;
            let tokio_file = tokio::fs::File::from_std(file);
            Ok(Box::new(PosixReadHandle::new(tokio_file)) as Box<dyn ReadAt>)
        })
    }

    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            check_deny_list_write(&at)?;
            self.create_dir_internal(&root_entry.root_doc_id, &at).await
        })
    }

    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            check_deny_list_write(&at)?;
            if at.as_str().is_empty() {
                return Err(VfsError::WrongKind);
            }

            let components: Vec<&str> = at.components().collect();
            let (target_name, parent_comps) = match components.split_last() {
                Some(pair) => pair,
                None => return Err(VfsError::NotFound),
            };

            let mut cur_parent_id = root_entry.root_doc_id.clone();
            for comp in parent_comps {
                let children = self.bridge.list_children(&cur_parent_id).await?;
                let parent_node = children
                    .into_iter()
                    .find(|n| n.display_name == *comp)
                    .ok_or(VfsError::NotFound)?;
                if parent_node.kind != EntryKind::Directory {
                    return Err(VfsError::WrongKind);
                }
                cur_parent_id = parent_node.doc_id;
            }

            let children = self.bridge.list_children(&cur_parent_id).await?;
            let file_doc_id = if let Some(existing) = children
                .into_iter()
                .find(|n| n.display_name == *target_name)
            {
                if existing.kind != EntryKind::File {
                    return Err(VfsError::WrongKind);
                }
                existing.doc_id
            } else {
                self.bridge.create_file(&cur_parent_id, target_name).await?
            };

            let file = self.bridge.open_file(&file_doc_id, "rw").await?;
            let tokio_file = tokio::fs::File::from_std(file);
            Ok(Box::new(PosixWriteHandle::new(tokio_file)) as Box<dyn WriteAt>)
        })
    }

    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        let from = from.clone();
        let to = to.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            check_deny_list_write(&from)?;
            check_deny_list(&to)?;
            if from.as_str().is_empty() || to.as_str().is_empty() {
                return Err(VfsError::WrongKind);
            }

            let from_components: Vec<&str> = from.components().collect();
            let from_node = self
                .resolve_node(&root_entry.root_doc_id, &from_components)
                .await?;

            let to_components: Vec<&str> = to.components().collect();
            let (to_target, to_parent_comps) = match to_components.split_last() {
                Some(pair) => pair,
                None => return Err(VfsError::NotFound),
            };

            if !to_parent_comps.is_empty() {
                let to_parent_rel = to_parent_comps.join("/");
                if let Ok(rel) = RelPath::new(&to_parent_rel) {
                    self.create_dir_internal(&root_entry.root_doc_id, &rel)
                        .await?;
                }
            }

            self.bridge.rename(&from_node.doc_id, to_target).await?;
            Ok(())
        })
    }

    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        let at = at.clone();
        Box::pin(async move {
            let root_entry = self.get_root(root)?;
            if root_entry.read_only {
                return Err(VfsError::ReadOnly);
            }
            check_deny_list_write(&at)?;
            if at.as_str().is_empty() {
                return Err(VfsError::WrongKind);
            }

            let components: Vec<&str> = at.components().collect();
            let node = self
                .resolve_node(&root_entry.root_doc_id, &components)
                .await?;
            if node.kind == EntryKind::Directory {
                let children = self.bridge.list_children(&node.doc_id).await?;
                if !children.is_empty() {
                    return Err(VfsError::WrongKind);
                }
            }
            self.bridge.remove(&node.doc_id).await?;
            Ok(())
        })
    }
}
