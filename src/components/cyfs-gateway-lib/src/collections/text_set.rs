use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;
use cyfs_process_chain::{SetCollection, SetCollectionTraverseCallBackRef};

pub struct TextSet {
    file_path: String,
    set: RwLock<HashSet<String>>,
}

impl TextSet {
    pub async fn load_from(file_path: impl Into<String>) -> Result<Self, String> {
        let file_path = file_path.into();
        let set = if Path::new(file_path.as_str()).exists() {
            let content = tokio::fs::read_to_string(file_path.as_str()).await.map_err(|e| e.to_string())?;
            if content.is_empty() {
                HashSet::new()
            } else {
                content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect()
            }
        } else {
            HashSet::new()
        };
        Ok(TextSet {
            file_path,
            set: RwLock::new(set),
        })
    }

    pub async fn save(&self) -> Result<(), String> {
        let file_path = self.file_path.clone();
        let content = {
            let set = self.set.read().unwrap();
            let mut lines: Vec<String> = set.iter().cloned().collect();
            lines.sort();
            lines.join("\n")
        };
        tokio::fs::write(file_path, content).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SetCollection for TextSet {
    async fn len(&self) -> Result<usize, String> {
        Ok(self.set.read().unwrap().len())
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        let inserted = {
            let mut set = self.set.write().unwrap();
            set.insert(value.to_string())
        };

        if inserted {
            self.save().await?;
        }
        Ok(inserted)
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        Ok(self.set.read().unwrap().contains(key))
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let removed = {
            self.set.write().unwrap().remove(key)
        };

        if removed {
            self.save().await?;
        }
        Ok(removed)
    }

    async fn get_all(&self) -> Result<Vec<String>, String> {
        Ok(self.set.read().unwrap().iter().cloned().collect())
    }

    async fn traverse(&self, callback: SetCollectionTraverseCallBackRef) -> Result<(), String> {
        let set = {
            self.set.read().unwrap().clone()
        };
        for item in set {
            callback.call(item.as_str()).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use super::*;

    #[tokio::test]
    async fn test_new_text_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let set = TextSet::load_from(path).await.unwrap();

        assert_eq!(set.len().await.unwrap(), 0);
        assert!(!set.contains("test").await.unwrap());
        assert!(set.insert("test").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 1);
        assert!(set.contains("test").await.unwrap());
        assert!(set.remove("test").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_reopen_text_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        {
            let set = TextSet::load_from(path.as_str()).await.unwrap();

            assert_eq!(set.len().await.unwrap(), 0);
            assert!(!set.contains("test").await.unwrap());
            assert!(set.insert("test").await.unwrap());
            assert_eq!(set.len().await.unwrap(), 1);
            assert!(set.contains("test").await.unwrap());
        }
        {
            let set = TextSet::load_from(path).await.unwrap();

            assert_eq!(set.len().await.unwrap(), 1);
            assert!(set.contains("test").await.unwrap());
            assert!(set.remove("test").await.unwrap());
            assert_eq!(set.len().await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn test_open_text_set() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"test1\ntest2\ntest3").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let set = TextSet::load_from(path).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 3);
        assert!(set.contains("test1").await.unwrap());
        assert!(set.contains("test2").await.unwrap());
        assert!(set.contains("test3").await.unwrap());
        assert!(set.remove("test2").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_empty_lines_and_duplicates() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"\ntest\n\nother\n\ntest\n").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let set = TextSet::load_from(path).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 2);
        assert!(set.contains("test").await.unwrap());
        assert!(set.contains("other").await.unwrap());
    }
}