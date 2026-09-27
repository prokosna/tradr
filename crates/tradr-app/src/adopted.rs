//! In-memory registry for staging platform-adopted file descriptors (ADR-0023).

use std::collections::HashMap;
use std::fs::File;
use std::sync::Mutex;

use tradr_core::{RelPath, RootId, Vfs};
use tradr_vfs::NativeVfs;

use crate::send::SendItem;

struct AdoptedEntry {
    file: File,
    name: String,
}

struct AdoptedState {
    next_id: u64,
    next_root_id: u64,
    files: HashMap<String, AdoptedEntry>,
}

impl Default for AdoptedState {
    fn default() -> Self {
        Self {
            next_id: 1,
            next_root_id: 1u64 << 32,
            files: HashMap::new(),
        }
    }
}

/// Holds open files adopted before the VFS exists so transfer offers can read them.
pub struct AdoptedFiles {
    state: Mutex<AdoptedState>,
}

impl Default for AdoptedFiles {
    fn default() -> Self {
        Self {
            state: Mutex::new(AdoptedState::default()),
        }
    }
}

impl AdoptedFiles {
    /// Creates an empty registry for staging adopted files.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps an adopted file until staged so Android descriptors stay valid across cold start.
    pub fn adopt(&self, file: File, name: &str) -> Result<String, String> {
        let rel = RelPath::new(name).map_err(|e| e.to_string())?;
        if rel.components().count() != 1 {
            return Err("adopted file name must be a single component".to_string());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "adopted files lock poisoned".to_string())?;
        let id = format!("adopted-{}", state.next_id);
        state.next_id += 1;
        state.files.insert(
            id.clone(),
            AdoptedEntry {
                file,
                name: name.to_string(),
            },
        );
        Ok(id)
    }

    /// Stages adopted files as single-file roots so transfers read them without assembling paths.
    pub async fn send_items(
        &self,
        vfs: &NativeVfs,
        ids: &[String],
    ) -> Result<Vec<SendItem>, String> {
        let mut registered_roots = Vec::new();
        match self
            .stage_ids_internal(vfs, ids, &mut registered_roots)
            .await
        {
            Ok(items) => Ok(items),
            Err(err) => {
                for root in registered_roots {
                    if let Err(e) = vfs.unregister_open_file(root) {
                        eprintln!("failed to unregister root {}: {e}", root.value());
                    }
                }
                Err(err)
            }
        }
    }

    async fn stage_ids_internal(
        &self,
        vfs: &NativeVfs,
        ids: &[String],
        registered_roots: &mut Vec<RootId>,
    ) -> Result<Vec<SendItem>, String> {
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            let (clone, name, root) = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "adopted files lock poisoned".to_string())?;
                let entry = state
                    .files
                    .get(id)
                    .ok_or_else(|| format!("unknown adopted file id: {id}"))?;
                let clone = entry
                    .file
                    .try_clone()
                    .map_err(|e| format!("failed to clone adopted file {id}: {e}"))?;
                let name = entry.name.clone();
                let root = RootId::new(state.next_root_id);
                state.next_root_id += 1;
                (clone, name, root)
            };

            vfs.register_open_file(root, clone, &name)
                .map_err(|e| format!("failed to register open file root: {e}"))?;
            registered_roots.push(root);

            let rel_path = RelPath::new(&name).map_err(|e| e.to_string())?;
            let meta = vfs
                .stat(root, &rel_path)
                .await
                .map_err(|e| format!("failed to stat adopted file {id}: {e}"))?;

            items.push(SendItem {
                root,
                rel_path,
                size_bytes: meta.size_bytes,
            });
        }
        Ok(items)
    }

    /// Releases staged roots so descriptor handles do not linger after a send.
    pub fn unstage(&self, vfs: &NativeVfs, items: &[SendItem]) -> Result<(), String> {
        let mut first_error = None;
        for item in items {
            if let Err(e) = vfs.unregister_open_file(item.root) {
                first_error.get_or_insert_with(|| {
                    format!("failed to unregister root {}: {e}", item.root.value())
                });
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Drops the adopted file so the descriptor closes once active transfers finish.
    pub fn release(&self, id: &str) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "adopted files lock poisoned".to_string())?;
        match state.files.remove(id) {
            Some(_) => Ok(()),
            None => Err(format!("unknown adopted file id: {id}")),
        }
    }
}
