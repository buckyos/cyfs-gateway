use super::var::VariableVisitorRef;
use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;

pub type AnyRef = Arc<dyn Any + Send + Sync>;

#[derive(Clone, Copy, Debug)]
pub enum NumberValue {
    Int(i64),
    Float(f64),
}

impl NumberValue {
    pub fn as_f64(&self) -> f64 {
        match self {
            NumberValue::Int(v) => *v as f64,
            NumberValue::Float(v) => *v,
        }
    }
}

impl std::fmt::Display for NumberValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NumberValue::Int(v) => write!(f, "{}", v),
            NumberValue::Float(v) => write!(f, "{}", v),
        }
    }
}

impl PartialEq for NumberValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NumberValue::Int(a), NumberValue::Int(b)) => a == b,
            // Keep strict variant equality to avoid surprising implicit numeric coercion.
            (NumberValue::Float(a), NumberValue::Float(b)) => a.to_bits() == b.to_bits(),
            _ => false,
        }
    }
}

impl Eq for NumberValue {}

#[derive(Clone)]
pub enum TypedValue {
    Null,
    Bool(bool),
    Number(NumberValue),
    String(String),
    List(ListCollectionRef),
    Set(SetCollectionRef),
    Map(MapCollectionRef),
    MultiMap(MultiMapCollectionRef),
    Visitor(VariableVisitorRef),
    Any(AnyRef),
}

pub enum TypedValueRef<'a> {
    Null,
    Bool(bool),
    Number(NumberValue),
    String(&'a str),
    List(&'a ListCollectionRef),
    Set(&'a SetCollectionRef),
    Map(&'a MapCollectionRef),
    MultiMap(&'a MultiMapCollectionRef),
    Visitor(&'a VariableVisitorRef),
    Any(&'a AnyRef),
}

// Backward-compatible aliases kept for existing call sites and scripts/docs.
pub type CollectionValue = TypedValue;
pub type CollectionValueRef<'a> = TypedValueRef<'a>;

impl std::fmt::Display for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypedValue::Null => write!(f, "null"),
            TypedValue::Bool(v) => write!(f, "{}", v),
            TypedValue::Number(v) => write!(f, "{}", v),
            TypedValue::String(s) => write!(f, "{}", s),
            TypedValue::List(_) => write!(f, "[List]"),
            TypedValue::Set(_) => write!(f, "[Set]"),
            TypedValue::Map(_) => write!(f, "[Map]"),
            TypedValue::MultiMap(_) => write!(f, "[MultiMap]"),
            TypedValue::Visitor(_) => write!(f, "[Visitor]"),
            TypedValue::Any(_) => write!(f, "[Any]"),
        }
    }
}

impl std::fmt::Debug for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Call the Display implementation for a cleaner output
        write!(f, "{}", self)
    }
}

impl PartialEq for TypedValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (TypedValue::Null, TypedValue::Null) => true,
            (TypedValue::Bool(a), TypedValue::Bool(b)) => a == b,
            (TypedValue::Number(a), TypedValue::Number(b)) => a == b,
            (TypedValue::String(a), TypedValue::String(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for TypedValue {}

impl TypedValue {
    pub fn compare_string(&self, other: &Self) -> Option<bool> {
        match (self, other) {
            (TypedValue::String(s1), TypedValue::String(s2)) => Some(s1 == s2),
            _ => None,
        }
    }

    pub fn get_type(&self) -> &str {
        match self {
            TypedValue::Null => "Null",
            TypedValue::Bool(_) => "Bool",
            TypedValue::Number(_) => "Number",
            TypedValue::String(_) => "String",
            TypedValue::List(_) => "List",
            TypedValue::Set(_) => "Set",
            TypedValue::Map(_) => "Map",
            TypedValue::MultiMap(_) => "MultiMap",
            TypedValue::Visitor(_) => "Visitor",
            TypedValue::Any(_) => "Any",
        }
    }

    pub fn is_string(&self) -> bool {
        matches!(self, TypedValue::String(_))
    }

    pub fn as_ref(&self) -> TypedValueRef<'_> {
        match self {
            TypedValue::Null => TypedValueRef::Null,
            TypedValue::Bool(v) => TypedValueRef::Bool(*v),
            TypedValue::Number(v) => TypedValueRef::Number(*v),
            TypedValue::String(s) => TypedValueRef::String(s.as_str()),
            TypedValue::List(l) => TypedValueRef::List(l),
            TypedValue::Set(s) => TypedValueRef::Set(s),
            TypedValue::Map(m) => TypedValueRef::Map(m),
            TypedValue::MultiMap(mm) => TypedValueRef::MultiMap(mm),
            TypedValue::Visitor(v) => TypedValueRef::Visitor(v),
            TypedValue::Any(a) => TypedValueRef::Any(a),
        }
    }

    pub fn into_string(self) -> Option<String> {
        if let TypedValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, TypedValue::Null)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, TypedValue::Bool(_))
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let TypedValue::Bool(v) = self {
            Some(*v)
        } else {
            None
        }
    }

    pub fn into_bool(self) -> Option<bool> {
        if let TypedValue::Bool(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn is_number(&self) -> bool {
        matches!(self, TypedValue::Number(_))
    }

    pub fn as_number(&self) -> Option<&NumberValue> {
        if let TypedValue::Number(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn into_number(self) -> Option<NumberValue> {
        if let TypedValue::Number(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let TypedValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn try_as_str(&self) -> Result<&str, String> {
        if let TypedValue::String(s) = self {
            Ok(s)
        } else {
            let msg = format!(
                "Expected TypedValue::String, found {}",
                self.get_type(),
            );
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn treat_as_str(&self) -> &str {
        match self {
            TypedValue::Null => "null",
            TypedValue::Bool(_) => "[Bool]",
            TypedValue::Number(_) => "[Number]",
            TypedValue::String(s) => s.as_str(),
            TypedValue::List(_) => "[List]",
            TypedValue::Set(_) => "[Set]",
            TypedValue::Map(_) => "[Map]",
            TypedValue::MultiMap(_) => "[MultiMap]",
            TypedValue::Visitor(_) => "[Visitor]",
            TypedValue::Any(_) => "[Any]",
        }
    }

    pub fn is_list(&self) -> bool {
        matches!(self, TypedValue::List(_))
    }

    pub fn as_list(&self) -> Option<&ListCollectionRef> {
        if let TypedValue::List(l) = self {
            Some(l)
        } else {
            None
        }
    }

    pub fn try_as_list(&self) -> Result<&ListCollectionRef, String> {
        if let TypedValue::List(l) = self {
            Ok(l)
        } else {
            let msg = format!("Expected TypedValue::List, found {}", self.get_type());
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn into_list(self) -> Option<ListCollectionRef> {
        if let TypedValue::List(l) = self {
            Some(l)
        } else {
            None
        }
    }

    pub fn is_set(&self) -> bool {
        matches!(self, TypedValue::Set(_))
    }

    pub fn as_set(&self) -> Option<&SetCollectionRef> {
        if let TypedValue::Set(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn try_as_set(&self) -> Result<&SetCollectionRef, String> {
        if let TypedValue::Set(s) = self {
            Ok(s)
        } else {
            let msg = format!("Expected TypedValue::Set, found {}", self.get_type(),);
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn into_set(self) -> Option<SetCollectionRef> {
        if let TypedValue::Set(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn is_map(&self) -> bool {
        matches!(self, TypedValue::Map(_))
    }

    pub fn as_map(&self) -> Option<&MapCollectionRef> {
        if let TypedValue::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn try_as_map(&self) -> Result<&MapCollectionRef, String> {
        if let TypedValue::Map(m) = self {
            Ok(m)
        } else {
            let msg = format!("Expected TypedValue::Map, found {}", self.get_type(),);
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn into_map(self) -> Option<MapCollectionRef> {
        if let TypedValue::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn is_multi_map(&self) -> bool {
        matches!(self, TypedValue::MultiMap(_))
    }

    pub fn as_multi_map(&self) -> Option<&MultiMapCollectionRef> {
        if let TypedValue::MultiMap(mm) = self {
            Some(mm)
        } else {
            None
        }
    }

    pub fn try_as_multi_map(&self) -> Result<&MultiMapCollectionRef, String> {
        if let TypedValue::MultiMap(mm) = self {
            Ok(mm)
        } else {
            let msg = format!(
                "Expected TypedValue::MultiMap, found {}",
                self.get_type(),
            );
            warn!("{}", msg);
            Err(msg)
        }
    }

    pub fn into_multi_map(self) -> Option<MultiMapCollectionRef> {
        if let TypedValue::MultiMap(mm) = self {
            Some(mm)
        } else {
            None
        }
    }

    pub fn is_collection(&self) -> bool {
        matches!(
            self,
            TypedValue::List(_)
                | TypedValue::Set(_)
                | TypedValue::Map(_)
                | TypedValue::MultiMap(_)
        )
    }

    pub fn as_visitor(&self) -> Option<&VariableVisitorRef> {
        if let TypedValue::Visitor(v) = self {
            Some(v)
        } else {
            None
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, TypedValue::Any(_))
    }

    pub fn as_any(&self) -> Option<&AnyRef> {
        if let TypedValue::Any(a) = self {
            Some(a)
        } else {
            None
        }
    }

    pub fn as_any_type<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        if let TypedValue::Any(a) = self {
            a.clone().downcast::<T>().ok()
        } else {
            None
        }
    }

    pub fn to_any_type<T: Any + Send + Sync + 'static>(self) -> Option<Arc<T>> {
        if let TypedValue::Any(a) = self {
            a.downcast::<T>().ok()
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionType {
    List,
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
pub trait SetCollectionTraverseCallBack: Send + Sync {
    /// Traverse the collection and apply the callback to each element.
    /// If the callback returns false, the traversal stops.
    async fn call(&self, key: &str) -> Result<bool, String>;
}

pub type SetCollectionTraverseCallBackRef = Arc<Box<dyn SetCollectionTraverseCallBack>>;

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

    /// Traverses the collection and applies the callback to each element.
    async fn traverse(&self, callback: SetCollectionTraverseCallBackRef) -> Result<(), String>;

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
pub trait ListCollectionTraverseCallBack: Send + Sync {
    /// Traverse the collection and apply the callback to each element.
    /// If the callback returns false, the traversal stops.
    async fn call(&self, index: usize, value: &TypedValue) -> Result<bool, String>;
}

pub type ListCollectionTraverseCallBackRef = Arc<Box<dyn ListCollectionTraverseCallBack>>;

#[async_trait::async_trait]
pub trait ListCollection: Send + Sync {
    /// Returns the number of elements in the collection.
    async fn len(&self) -> Result<usize, String>;

    /// Appends a value to the end of the list.
    async fn push(&self, value: TypedValue) -> Result<(), String>;

    /// Inserts a value at the specified index.
    async fn insert(&self, index: usize, value: TypedValue) -> Result<(), String>;

    /// Sets the value at the specified index.
    /// Returns previous value if index already existed.
    async fn set(
        &self,
        index: usize,
        value: TypedValue,
    ) -> Result<Option<TypedValue>, String>;

    /// Gets the value at the specified index.
    async fn get(&self, index: usize) -> Result<Option<TypedValue>, String>;

    /// Removes the value at the specified index.
    async fn remove(&self, index: usize) -> Result<Option<TypedValue>, String>;

    /// Pops the last value from the list.
    async fn pop(&self) -> Result<Option<TypedValue>, String>;

    /// Clears all values in the list.
    async fn clear(&self) -> Result<(), String>;

    /// Gets all values in the list.
    async fn get_all(&self) -> Result<Vec<TypedValue>, String>;

    /// Traverses the list and applies the callback to each element.
    async fn traverse(&self, callback: ListCollectionTraverseCallBackRef) -> Result<(), String>;

    /// Checks if all string values are present in the list.
    /// This is optimized for commands like `match-include` and only matches string elements.
    async fn contains_all_strings(&self, values: &[String]) -> Result<bool, String>;

    /// Checks if the collection is flushable.
    fn is_flushable(&self) -> bool {
        false
    }

    /// Flushes the collection to persistent storage if applicable.
    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }

    /// Dumps the collection to a vector of values.
    async fn dump(&self) -> Result<Vec<TypedValue>, String> {
        self.get_all().await
    }
}

pub type ListCollectionRef = Arc<Box<dyn ListCollection>>;

#[async_trait::async_trait]
pub trait MapCollectionTraverseCallBack: Send + Sync {
    /// Traverse the collection and apply the callback to each key-value pair.
    /// If the callback returns false, the traversal stops.
    async fn call(&self, key: &str, value: &TypedValue) -> Result<bool, String>;
}

pub type MapCollectionTraverseCallBackRef = Arc<Box<dyn MapCollectionTraverseCallBack>>;

#[async_trait::async_trait]
pub trait MapCollection: Send + Sync {
    /// Returns the number of elements in the collection.
    async fn len(&self) -> Result<usize, String>;

    /// Inserts a key-value pair into the collection.
    /// If the key already exists, it will return false.
    async fn insert_new(&self, key: &str, value: TypedValue) -> Result<bool, String>;

    /// Sets the value for the given key in the collection.
    async fn insert(
        &self,
        key: &str,
        value: TypedValue,
    ) -> Result<Option<TypedValue>, String>;

    /// Gets the value for the given key from the collection.
    async fn get(&self, key: &str) -> Result<Option<TypedValue>, String>;

    /// Checks if the collection contains the given key.
    async fn contains_key(&self, key: &str) -> Result<bool, String>;

    /// Removes the key from the collection.
    async fn remove(&self, key: &str) -> Result<Option<TypedValue>, String>;

    // Traverses the collection and applies the callback to each key-value pair.
    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String>;

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
    async fn dump(&self) -> Result<Vec<(String, TypedValue)>, String>;
}

pub type MapCollectionRef = Arc<Box<dyn MapCollection>>;

#[async_trait::async_trait]
pub trait MultiMapCollectionTraverseCallBack: Send + Sync {
    /// Traverse the collection and apply the callback to each key-value pair.
    /// If the callback returns false, the traversal stops.
    async fn call(&self, key: &str, value: &str) -> Result<bool, String>;
}

pub type MultiMapCollectionTraverseCallBackRef = Arc<Box<dyn MultiMapCollectionTraverseCallBack>>;

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
    async fn remove_many(
        &self,
        key: &str,
        values: &[&str],
    ) -> Result<Option<SetCollectionRef>, String>;

    /// Removes all values for the given key from the collection.
    /// If the key is not found, it returns false.
    async fn remove_all(&self, key: &str) -> Result<Option<SetCollectionRef>, String>;

    /// Traverses the collection and applies the callback to each key-value pair.
    async fn traverse(&self, callback: MultiMapCollectionTraverseCallBackRef)
        -> Result<(), String>;

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
