use super::var::VariableVisitorRef;
use std::sync::Arc;
use std::collections::HashSet;
use std::any::Any;

pub type AnyRef = Arc<dyn Any + Send + Sync>;
#[derive(Clone)]
pub enum CollectionValue {
    String(String),
    Set(SetCollectionRef),
    Map(MapCollectionRef),
    MultiMap(MultiMapCollectionRef),
    Visitor(VariableVisitorRef),
    Any(AnyRef),
}

pub enum CollectionValueRef<'a> {
    String(&'a str),
    Set(&'a SetCollectionRef),
    Map(&'a MapCollectionRef),
    MultiMap(&'a MultiMapCollectionRef),
    Visitor(&'a VariableVisitorRef),
    Any(&'a AnyRef),
}

impl std::fmt::Display for CollectionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectionValue::String(s) => write!(f, "{}", s),
            CollectionValue::Set(_) => write!(f, "[Set]"),
            CollectionValue::Map(_) => write!(f, "[Map]"),
            CollectionValue::MultiMap(_) => write!(f, "[MultiMap]"),
            CollectionValue::Visitor(_) => write!(f, "[Visitor]"),
            CollectionValue::Any(_) => write!(f, "[Any]"),
        }
    }
}

impl std::fmt::Debug for CollectionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Call the Display implementation for a cleaner output
        write!(f, "{}", self)
    }
}

impl PartialEq for CollectionValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CollectionValue::String(a), CollectionValue::String(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for CollectionValue {}

impl CollectionValue {
    pub fn compare_string(&self, other: &Self) -> Option<bool> {
        match (self, other) {
            (CollectionValue::String(s1), CollectionValue::String(s2)) => Some(s1 == s2),
            _ => None,
        }
    }

    pub fn get_type(&self) -> &str {
        match self {
            CollectionValue::String(_) => "String",
            CollectionValue::Set(_) => "Set",
            CollectionValue::Map(_) => "Map",
            CollectionValue::MultiMap(_) => "MultiMap",
            CollectionValue::Visitor(_) => "Visitor",
            CollectionValue::Any(_) => "Any",
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, CollectionValue::String(_))
    }
    
    pub fn as_ref(&self) -> CollectionValueRef {
        match self {
            CollectionValue::String(s) => CollectionValueRef::String(s.as_str()),
            CollectionValue::Set(s) => CollectionValueRef::Set(s),
            CollectionValue::Map(m) => CollectionValueRef::Map(m),
            CollectionValue::MultiMap(mm) => CollectionValueRef::MultiMap(mm),
            CollectionValue::Visitor(v) => CollectionValueRef::Visitor(v),
            CollectionValue::Any(a) => CollectionValueRef::Any(a),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let CollectionValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn try_as_str(&self) -> Result<&str, String> {
        if let CollectionValue::String(s) = self {
            Ok(s)
        } else {
            let msg = format!(
                "Expected CollectionValue::String, found {}",
                self.get_type(),
            );
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn treat_as_str(&self) -> &str {
        match self {
            CollectionValue::String(s) => s.as_str(),
            CollectionValue::Set(_) => "[Set]",
            CollectionValue::Map(_) => "[Map]",
            CollectionValue::MultiMap(_) => "[MultiMap]",
            CollectionValue::Visitor(_) => "[Visitor]",
            CollectionValue::Any(_) => "[Any]",
        }
    }

    pub fn as_set(&self) -> Option<&SetCollectionRef> {
        if let CollectionValue::Set(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn try_as_set(&self) -> Result<&SetCollectionRef, String> {
        if let CollectionValue::Set(s) = self {
            Ok(s)
        } else {
            let msg = format!("Expected CollectionValue::Set, found {}", self.get_type(),);
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn as_map(&self) -> Option<&MapCollectionRef> {
        if let CollectionValue::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn try_as_map(&self) -> Result<&MapCollectionRef, String> {
        if let CollectionValue::Map(m) = self {
            Ok(m)
        } else {
            let msg = format!("Expected CollectionValue::Map, found {}", self.get_type(),);
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn as_multi_map(&self) -> Option<&MultiMapCollectionRef> {
        if let CollectionValue::MultiMap(mm) = self {
            Some(mm)
        } else {
            None
        }
    }

    pub fn try_as_multi_map(&self) -> Result<&MultiMapCollectionRef, String> {
        if let CollectionValue::MultiMap(mm) = self {
            Ok(mm)
        } else {
            let msg = format!(
                "Expected CollectionValue::MultiMap, found {}",
                self.get_type(),
            );
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            CollectionValue::Set(_) | CollectionValue::Map(_) | CollectionValue::MultiMap(_)
        )
    }
    
    pub fn as_visitor(&self) -> Option<&VariableVisitorRef> {
        if let CollectionValue::Visitor(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, CollectionValue::Any(_))
    }

    pub fn as_any(&self) -> Option<&AnyRef> {
        if let CollectionValue::Any(a) = self {
            Some(a)
        } else {
            None
        }
    }

    pub fn as_any_type<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        if let CollectionValue::Any(a) = self {
            a.clone().downcast::<T>().ok()
        } else {
            None
        }
    }

    pub fn to_any_type<T: Any + Send + Sync + 'static>(self) -> Option<Arc<T>> {
        if let CollectionValue::Any(a) = self {
            a.downcast::<T>().ok()
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionType {
    Set,
    Map,
    MultiMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionFileFormat {
    Json,
    Sqlite,
}

#[async_trait::async_trait]
pub trait SetCollection: Send + Sync {
    /// Returns the number of elements in the collection.
    async fn len(&self) -> Result<usize, String>;

    /// Sets the collection with the given value.
    async fn insert(&self, value: &str) -> Result<bool, String>;

    /// Check if the collection contains the given value.
    async fn contains(&self, key: &str) -> Result<bool, String>;

    /// Removes the value from the collection.
    async fn remove(&self, key: &str) -> Result<bool, String>;

    /// Gets all values in the collection.
    async fn get_all(&self) -> Result<Vec<String>, String>;

    /// Checks if the collection is flushable.
    fn is_flushable(&self) -> bool {
        // Default implementation returns false, can be overridden by specific collections
        false
    }

    /// Flushes the collection to persistent storage if applicable.
    async fn flush(&self) -> Result<(), String> {
        // Default implementation does nothing, can be overridden by specific collections
        Ok(())
    }

    async fn dump(&self) -> Result<Vec<String>, String> {
        self.get_all().await
    }
}

pub type SetCollectionRef = Arc<Box<dyn SetCollection>>;

#[async_trait::async_trait]
pub trait MapCollection: Send + Sync {
    /// Returns the number of elements in the collection.
    async fn len(&self) -> Result<usize, String>;

    /// Inserts a key-value pair into the collection.
    /// If the key already exists, it will return false.
    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String>;

    /// Sets the value for the given key in the collection.
    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String>;

    /// Gets the value for the given key from the collection.
    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String>;

    /// Checks if the collection contains the given key.
    async fn contains_key(&self, key: &str) -> Result<bool, String>;

    /// Removes the key from the collection.
    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String>;

    /// Checks if the collection is flushable.
    fn is_flushable(&self) -> bool {
        // Default implementation returns false, can be overridden by specific collections
        false
    }

    /// Flushes the collection to persistent storage if applicable.
    async fn flush(&self) -> Result<(), String> {
        // Default implementation does nothing, can be overridden by specific collections
        Ok(())
    }

    /// Dumps the collection to a vector of strings.
    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String>;
}

pub type MapCollectionRef = Arc<Box<dyn MapCollection>>;

#[async_trait::async_trait]
pub trait MultiMapCollection: Send + Sync {
    /// Returns the number of elements in the collection.
    async fn len(&self) -> Result<usize, String>;

    /// Sets the value for the given key in the collection.
    async fn insert(&self, key: &str, value: &str) -> Result<bool, String>;

    /// Inserts multiple values for the given key in the collection.
    async fn insert_many(&self, key: &str, values: &[&str]) -> Result<bool, String>;

    /// Gets first value for the given key from the collection.
    async fn get(&self, key: &str) -> Result<Option<String>, String>;

    /// Gets all values for the given key from the collection.
    async fn get_many(&self, keys: &str) -> Result<Option<SetCollectionRef>, String>;

    /// Checks if the collection contains the given key.
    async fn contains_key(&self, key: &str) -> Result<bool, String>;

    /// Checks if the collection contains the given values for the key.
    /// If all values are present, it returns true.
    /// If any value is missing, it returns false.
    async fn contains_value(&self, key: &str, value: &[&str]) -> Result<bool, String>;

    /// Removes the value for the given key from the collection.
    /// If the key or value is not found, it returns false.
    async fn remove(&self, key: &str, value: &str) -> Result<bool, String>;

    /// Removes the values for the given key from the collection.
    /// if any value is removed, it returns true
    async fn remove_many(&self, key: &str, values: &[&str]) -> Result<Option<SetCollectionRef>, String>;

    /// Removes all values for the given key from the collection.
    /// If the key is not found, it returns false.
    async fn remove_all(&self, key: &str) -> Result<Option<SetCollectionRef>, String>;

    /// Checks if the collection is flushable.
    fn is_flushable(&self) -> bool {
        // Default implementation returns false, can be overridden by specific collections
        false
    }

    /// Flushes the collection to persistent storage if applicable.
    async fn flush(&self) -> Result<(), String> {
        // Default implementation does nothing, can be overridden by specific collections
        Ok(())
    }

    /// Dumps the collection to a vector of key-value pairs.
    async fn dump(&self) -> Result<Vec<(String, HashSet<String>)>, String>;
}

pub type MultiMapCollectionRef = Arc<Box<dyn MultiMapCollection>>;
