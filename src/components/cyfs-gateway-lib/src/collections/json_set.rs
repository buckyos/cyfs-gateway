use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;
use cyfs_process_chain::{SetCollection, SetCollectionTraverseCallBackRef};

pub struct JsonSet {
    file_path: String,
    set: RwLock<HashSet<String>>,
}

impl JsonSet {
    pub async fn load_from(file_path: impl Into<String>) -> Result<Self, String> {
        let file_path = file_path.into();
        let set = if Path::new(file_path.as_str()).exists() {
            let content = tokio::fs::read_to_string(file_path.as_str()).await.map_err(|e| e.to_string())?;
            if content.is_empty() {
                HashSet::new()
            } else {
                let set = serde_json::from_str::<HashSet<String>>(&content).map_err(|e| e.to_string())?;
                set
            }
        } else {
            HashSet::new()
        };
        Ok(JsonSet {
            file_path,
            set: RwLock::new(set),
        })
    }

    pub async fn save(&self) -> Result<(), String> {
        let file_path = self.file_path.clone();
        let content = {
            let set = self.set.read().unwrap();
            serde_json::to_string_pretty(&*set).map_err(|e| e.to_string())?
        };
        tokio::fs::write(file_path, content).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SetCollection for JsonSet {
    async fn len(&self) -> Result<usize, String> {
        Ok(self.set.read().unwrap().len())
    }

    async fn insert(&self, value: &str) -> Result<bool, String> {
        {
            self.set.write().unwrap().insert(value.to_string());
        }
        self.save().await?;
        Ok(true)
    }

    async fn contains(&self, key: &str) -> Result<bool, String> {
        Ok(self.set.read().unwrap().contains(key))
    }

    async fn remove(&self, key: &str) -> Result<bool, String> {
        let ret = {
            self.set.write().unwrap().remove(key)
        };
        if ret {
            self.save().await?;
        }
        Ok(ret)
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
    async fn test_new_json_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        let set = JsonSet::load_from(path).await.unwrap();

        assert_eq!(set.len().await.unwrap(), 0);
        assert!(!set.contains("test").await.unwrap());
        assert!(set.insert("test").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 1);
        assert!(set.contains("test").await.unwrap());
        assert!(set.remove("test").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_reopen_json_set() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_string_lossy().to_string();
        {
            let set = JsonSet::load_from(path.as_str()).await.unwrap();

            assert_eq!(set.len().await.unwrap(), 0);
            assert!(!set.contains("test").await.unwrap());
            assert!(set.insert("test").await.unwrap());
            assert_eq!(set.len().await.unwrap(), 1);
            assert!(set.contains("test").await.unwrap());
        }
        {
            let set = JsonSet::load_from(path).await.unwrap();
            assert_eq!(set.len().await.unwrap(), 1);
            assert!(set.contains("test").await.unwrap());
            assert!(set.remove("test").await.unwrap());
            assert_eq!(set.len().await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn test_open_json_set() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"[\"test\"]").unwrap();
        let path = file.path().to_string_lossy().to_string();

        let set = JsonSet::load_from(path).await.unwrap();
        assert_eq!(set.len().await.unwrap(), 1);
        assert_eq!(set.get_all().await.unwrap(), vec!["test"]);
        assert!(set.contains("test").await.unwrap());
        assert!(set.remove("test").await.unwrap());
        assert_eq!(set.len().await.unwrap(), 0);
    }
}