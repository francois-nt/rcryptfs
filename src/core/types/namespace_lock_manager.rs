use crate::core::{VirtualPath, VirtualPathBuf};
use parking_lot::{Condvar, Mutex};

struct NamespaceScope {
    id: u64,
    exclusive: bool,
    paths: Vec<VirtualPathBuf>,
}

#[derive(Default)]
struct NamespaceLockState {
    next_id: u64,
    active: Vec<NamespaceScope>,
    waiting: Vec<NamespaceScope>,
}

/// Coordinates overlapping namespace mutations within one storage instance.
#[derive(Default)]
pub(super) struct NamespaceLockManager {
    state: Mutex<NamespaceLockState>,
    changed: Condvar,
}

/// Releases an acquired namespace scope when dropped.
pub(super) struct NamespaceScopeGuard<'a> {
    manager: &'a NamespaceLockManager,
    id: u64,
}

impl NamespaceLockManager {
    /// Acquires a scope compatible with other ordinary namespace mutations.
    pub(super) fn acquire_shared<I, P>(&self, paths: I) -> std::io::Result<NamespaceScopeGuard<'_>>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<VirtualPath>,
    {
        self.acquire(false, paths)
    }

    /// Acquires a scope excluding every overlapping namespace mutation.
    pub(super) fn acquire_exclusive<I, P>(
        &self,
        paths: I,
    ) -> std::io::Result<NamespaceScopeGuard<'_>>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<VirtualPath>,
    {
        self.acquire(true, paths)
    }

    fn acquire<I, P>(&self, exclusive: bool, paths: I) -> std::io::Result<NamespaceScopeGuard<'_>>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<VirtualPath>,
    {
        let paths = normalize_scope(paths)?;
        let mut state = self.state.lock();

        let id = state.next_id;
        state.next_id = id
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("namespace lock identifier overflow"))?;

        state.waiting.push(NamespaceScope {
            id,
            exclusive,
            paths,
        });

        loop {
            let position = state
                .waiting
                .iter()
                .position(|scope| scope.id == id)
                .ok_or_else(|| std::io::Error::other("waiting namespace scope disappeared"))?;

            if can_activate(&state, position) {
                let scope = state.waiting.remove(position);
                state.active.push(scope);
                return Ok(NamespaceScopeGuard { manager: self, id });
            }
            self.changed.wait(&mut state);
        }
    }
}

impl Drop for NamespaceScopeGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.manager.state.lock();
        let Some(position) = state.active.iter().position(|scope| scope.id == self.id) else {
            log::error!("active namespace scope disappeared");
            return;
        };
        state.active.swap_remove(position);
        self.manager.changed.notify_all();
    }
}

/// Checks active scopes and earlier conflicting waiters.
fn can_activate(state: &NamespaceLockState, position: usize) -> bool {
    let request = &state.waiting[position];
    !state
        .active
        .iter()
        .chain(&state.waiting[..position])
        .any(|scope| conflicts(request, scope))
}

/// Returns whether two scopes need exclusive access to overlapping paths.
fn conflicts(a: &NamespaceScope, b: &NamespaceScope) -> bool {
    (a.exclusive || b.exclusive)
        && a.paths.iter().any(|a| {
            b.paths
                .iter()
                .any(|b| a.is_ancestor_or_same(b) || b.is_ancestor_or_same(a))
        })
}

/// Normalizes, deduplicates, and removes redundant descendant paths.
fn normalize_scope<I, P>(paths: I) -> std::io::Result<Vec<VirtualPathBuf>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<VirtualPath>,
{
    let mut paths: Vec<_> = paths
        .into_iter()
        .map(|path| path.as_ref().normalize())
        .collect::<std::io::Result<_>>()?;

    paths.sort_unstable();
    paths.dedup_by(|path, parent| parent.is_ancestor_or_same(path.as_path()));

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };

    fn wait_for_waiters(manager: &NamespaceLockManager, count: usize) {
        for _ in 0..10_000 {
            if manager.state.lock().waiting.len() == count {
                return;
            }
            std::thread::yield_now();
        }
        panic!("namespace scope was not queued");
    }

    #[test]
    fn shared_scopes_may_overlap() {
        let manager = NamespaceLockManager::default();
        let _parent = manager.acquire_shared([VirtualPath::new("a")]).unwrap();
        let _child = manager.acquire_shared([VirtualPath::new("a/b")]).unwrap();

        assert_eq!(manager.state.lock().active.len(), 2);
    }

    #[test]
    fn exclusive_scope_blocks_overlapping_paths() {
        let manager = Arc::new(NamespaceLockManager::default());
        let parent = manager.acquire_exclusive([VirtualPath::new("a")]).unwrap();
        let contender = Arc::clone(&manager);
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _guard = contender.acquire_shared([VirtualPath::new("a/b")]).unwrap();
            acquired_tx.send(()).unwrap();
        });

        wait_for_waiters(&manager, 1);
        assert!(acquired_rx.try_recv().is_err());
        drop(parent);
        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn exclusive_scope_does_not_block_disjoint_paths() {
        let manager = NamespaceLockManager::default();
        let _left = manager.acquire_exclusive([VirtualPath::new("a")]).unwrap();
        let _right = manager.acquire_exclusive([VirtualPath::new("b")]).unwrap();

        assert_eq!(manager.state.lock().active.len(), 2);
    }

    #[test]
    fn queued_exclusive_scope_precedes_later_overlapping_shared_scope() {
        let manager = Arc::new(NamespaceLockManager::default());
        let initial = manager.acquire_shared([VirtualPath::new("a")]).unwrap();
        let (order_tx, order_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let exclusive_manager = Arc::clone(&manager);
        let exclusive_order = order_tx.clone();
        let exclusive = std::thread::spawn(move || {
            let _guard = exclusive_manager
                .acquire_exclusive([VirtualPath::new("a")])
                .unwrap();
            exclusive_order.send("exclusive").unwrap();
            release_rx.recv().unwrap();
        });
        wait_for_waiters(&manager, 1);

        let shared_manager = Arc::clone(&manager);
        let shared = std::thread::spawn(move || {
            let _guard = shared_manager
                .acquire_shared([VirtualPath::new("a/b")])
                .unwrap();
            order_tx.send("shared").unwrap();
        });
        wait_for_waiters(&manager, 2);

        drop(initial);
        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "exclusive"
        );
        assert!(order_rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        assert_eq!(
            order_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            "shared"
        );
        exclusive.join().unwrap();
        shared.join().unwrap();
    }

    #[test]
    fn scope_paths_are_normalized_and_reduced() {
        let scope = normalize_scope([
            VirtualPath::new("a/./b/../c"),
            VirtualPath::new("a"),
            VirtualPath::new("d"),
        ])
        .unwrap();

        assert_eq!(
            scope,
            [VirtualPathBuf::from("a"), VirtualPathBuf::from("d")]
        );
    }
}
