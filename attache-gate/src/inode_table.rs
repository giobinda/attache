use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fuser::INodeNo;

/// Maps FUSE inode numbers to real backing-filesystem paths and back.
/// The root directory is always inode 1.
pub struct InodeTable {
    paths: HashMap<INodeNo, PathBuf>,
    by_path: HashMap<PathBuf, INodeNo>,
    next: u64,
}

impl InodeTable {
    pub fn new(root: PathBuf) -> Self {
        let mut paths = HashMap::new();
        let mut by_path = HashMap::new();
        paths.insert(INodeNo::ROOT, root.clone());
        by_path.insert(root, INodeNo::ROOT);
        Self {
            paths,
            by_path,
            next: 2,
        }
    }

    pub fn path(&self, ino: INodeNo) -> Option<PathBuf> {
        self.paths.get(&ino).cloned()
    }

    /// Returns the existing inode for `path`, allocating a new one if this
    /// path hasn't been seen before.
    pub fn ino_for(&mut self, path: PathBuf) -> INodeNo {
        if let Some(ino) = self.by_path.get(&path) {
            return *ino;
        }
        let ino = INodeNo(self.next);
        self.next += 1;
        self.paths.insert(ino, path.clone());
        self.by_path.insert(path, ino);
        ino
    }

    /// Updates the table when a path is renamed/moved, keeping its inode
    /// number stable across the rename.
    pub fn rename(&mut self, old: &Path, new: PathBuf) {
        if let Some(ino) = self.by_path.remove(old) {
            self.paths.insert(ino, new.clone());
            self.by_path.insert(new, ino);
        }
    }

    /// Drops a path from the table, e.g. after unlink/rmdir.
    pub fn forget_path(&mut self, path: &Path) {
        if let Some(ino) = self.by_path.remove(path) {
            self.paths.remove(&ino);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_inode_one() {
        let table = InodeTable::new(PathBuf::from("/backing"));
        assert_eq!(table.path(INodeNo::ROOT), Some(PathBuf::from("/backing")));
    }

    #[test]
    fn allocates_a_fresh_inode_for_a_new_path() {
        let mut table = InodeTable::new(PathBuf::from("/backing"));

        let ino = table.ino_for(PathBuf::from("/backing/a.txt"));

        assert_ne!(ino, INodeNo::ROOT);
        assert_eq!(table.path(ino), Some(PathBuf::from("/backing/a.txt")));
    }

    #[test]
    fn repeated_lookup_of_the_same_path_reuses_its_inode() {
        let mut table = InodeTable::new(PathBuf::from("/backing"));

        let first = table.ino_for(PathBuf::from("/backing/a.txt"));
        let second = table.ino_for(PathBuf::from("/backing/a.txt"));

        assert_eq!(first, second);
    }

    #[test]
    fn different_paths_get_different_inodes() {
        let mut table = InodeTable::new(PathBuf::from("/backing"));

        let a = table.ino_for(PathBuf::from("/backing/a.txt"));
        let b = table.ino_for(PathBuf::from("/backing/b.txt"));

        assert_ne!(a, b);
    }

    #[test]
    fn rename_keeps_the_same_inode_under_the_new_path() {
        let mut table = InodeTable::new(PathBuf::from("/backing"));
        let ino = table.ino_for(PathBuf::from("/backing/a.txt"));

        table.rename(Path::new("/backing/a.txt"), PathBuf::from("/backing/b.txt"));

        assert_eq!(table.path(ino), Some(PathBuf::from("/backing/b.txt")));
    }

    #[test]
    fn forget_path_removes_it_from_the_table() {
        let mut table = InodeTable::new(PathBuf::from("/backing"));
        let ino = table.ino_for(PathBuf::from("/backing/a.txt"));

        table.forget_path(Path::new("/backing/a.txt"));

        assert_eq!(table.path(ino), None);
    }
}
