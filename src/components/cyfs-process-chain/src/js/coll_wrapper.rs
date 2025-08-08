use super::exec::RuntimeHandleWrapper;
use crate::collection::*;
use boa_engine::{
    Context as JsContext, Finalize, JsData, JsError, JsNativeError, JsObject, JsResult, JsString,
    JsValue, NativeFunction, Trace,
    class::{Class, ClassBuilder},
    js_string,
    object::builtins::JsArray,
    value::TryFromJs,
};
use boa_gc::Tracer;
use std::sync::Arc;

pub struct CollectionWrapperHelper {}

impl CollectionWrapperHelper {
    pub fn register_all(context: &mut JsContext) -> Result<(), String> {
        SetCollectionWrapper::register(context)?;
        MapCollectionWrapper::register(context)?;
        MultiMapCollectionWrapper::register(context)?;

        Ok(())
    }

    pub fn collection_value_to_js_value(
        value: CollectionValue,
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        match value {
            CollectionValue::String(s) => Ok(JsValue::String(JsString::from(s))),
            CollectionValue::Map(map) => {
                let wrapper = MapCollectionWrapper::new(map);
                wrapper.into_js_object(context).map(JsValue::Object)
            }
            CollectionValue::Set(set) => {
                let wrapper = SetCollectionWrapper::new(set);
                wrapper.into_js_object(context).map(JsValue::Object)
            }
            CollectionValue::MultiMap(map) => {
                let wrapper = MultiMapCollectionWrapper::new(map);
                wrapper.into_js_object(context).map(JsValue::Object)
            }
            _ => {
                let msg = format!("Unsupported CollectionValue type: {:?}", value);
                warn!("{}", msg);
                Ok(JsValue::Null)
            }
        }
    }

    pub fn js_value_to_collection_value(value: &JsValue) -> JsResult<CollectionValue> {
        if value.is_string() {
            let s = value
                .as_string()
                .map(|s| s.to_std_string_escaped())
                .ok_or_else(|| JsNativeError::error().with_message("Expected a string value"))?;
            Ok(CollectionValue::String(s))
        } else if value.is_object() {
            let obj = value
                .as_object()
                .ok_or_else(|| JsNativeError::error().with_message("Expected an object value"))?;

            if let Some(wrapper) = obj.downcast_ref::<SetCollectionWrapper>() {
                Ok(CollectionValue::Set(wrapper.collection.clone()))
            } else if let Some(wrapper) = obj.downcast_ref::<MapCollectionWrapper>() {
                Ok(CollectionValue::Map(wrapper.collection.clone()))
            } else {
                let msg = "Expected a valid CollectionValue object".to_string();
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        } else {
            let msg = "Expected a string or object value".to_string();
            error!("{}", msg);
            Err(JsNativeError::error().with_message(msg).into())
        }
    }

    pub fn js_value_to_string_list(
        value: &JsValue,
        context: &mut JsContext,
    ) -> JsResult<Vec<String>> {
        match JsArray::try_from_js(value, context) {
            Ok(array) => {
                let len = match array.length(context) {
                    Ok(len) => len,
                    Err(e) => {
                        let msg = format!("Failed to get array length: {}", e);
                        error!("{}", msg);
                        return Err(JsNativeError::error().with_message(msg).into());
                    }
                };

                let mut list = Vec::with_capacity(len as usize);
                for i in 0..len {
                    let value = match array.get(i, context) {
                        Ok(v) => v,
                        Err(e) => {
                            let msg = format!("Failed to get array element at index {}: {}", i, e);
                            error!("{}", msg);
                            return Err(JsNativeError::error().with_message(msg).into());
                        }
                    };

                    if !value.is_string() {
                        let msg =
                            format!("Expected a string value at index {}, got {:?}", i, value);
                        error!("{}", msg);
                        return Err(JsNativeError::error().with_message(msg).into());
                    }

                    list.push(value.as_string().unwrap().to_std_string_escaped());
                }

                Ok(list)
            }
            Err(e) => {
                let msg = format!("Invalid argument: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }
}

#[derive(Clone, JsData, Finalize)]
pub struct SetCollectionWrapper {
    collection: SetCollectionRef,
}

impl SetCollectionWrapper {
    pub fn new(collection: SetCollectionRef) -> Self {
        Self { collection }
    }

    pub fn register(context: &mut JsContext) -> Result<(), String> {
        context.register_global_class::<Self>().map_err(|e| {
            let msg = format!("Failed to register SetCollectionWrapper: {}", e);
            error!("{}", msg);
            msg
        })
    }

    pub fn into_js_object(self, context: &mut JsContext) -> JsResult<JsObject> {
        // Get the prototype from the context registry
        let prototype = context
            .get_global_class::<SetCollectionWrapper>()
            .ok_or_else(|| {
                JsNativeError::error().with_message("SetCollectionWrapper prototype not found")
            })?
            .prototype();

        // Create a new JsObject with the prototype and data
        let js_obj = JsObject::from_proto_and_data(prototype, self);
        Ok(js_obj)
    }

    fn insert(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "Expected at least one argument".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let value = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string value"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.insert(&value)) {
            Ok(inserted) => Ok(JsValue::Boolean(inserted)),
            Err(e) => {
                let msg = format!("Failed to insert into set collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn contains(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.contains(&key)) {
            Ok(contains) => Ok(JsValue::Boolean(contains)),
            Err(e) => {
                let msg = format!("Failed to check if set contains key '{}': {}", key, e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn remove(this: &JsValue, args: &[JsValue], _context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = _context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.remove(&key)) {
            Ok(removed) => Ok(JsValue::Boolean(removed)),
            Err(e) => {
                let msg = format!("Failed to remove key '{}' from set collection: {}", key, e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn get_all(this: &JsValue, _args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.get_all()) {
            Ok(values) => {
                let values_iter = values
                    .into_iter()
                    .map(|x| JsValue::String(JsString::from(x)));
                let array = JsArray::from_iter(values_iter, context);
                Ok(JsValue::from(array))
            }
            Err(e) => Err(JsNativeError::error().with_message(e).into()),
        }
    }
}

unsafe impl Trace for SetCollectionWrapper {
    unsafe fn trace(&self, _tracer: &mut Tracer) {
        // No need to trace any JavaScript objects, as collection is Arc<dyn SetCollection>
        // Arc itself manages memory, garbage collector does not need to intervene
    }

    unsafe fn trace_non_roots(&self) {
        // No need to trace non-root objects, as there are no references to JavaScript objects
    }

    fn run_finalizer(&self) {
        // No special finalization needed, Arc will handle memory management
    }
}

impl Class for SetCollectionWrapper {
    const NAME: &'static str = "SetCollection";
    const LENGTH: usize = 0;

    fn init(class: &mut ClassBuilder) -> JsResult<()> {
        let insert_fn = NativeFunction::from_fn_ptr(Self::insert);
        class.method(js_string!("insert"), 1, insert_fn);

        let contains_fn = NativeFunction::from_fn_ptr(Self::contains);
        class.method(js_string!("contains"), 1, contains_fn);

        let remove_fn = NativeFunction::from_fn_ptr(Self::remove);
        class.method(js_string!("remove"), 1, remove_fn);

        let get_all_fn = NativeFunction::from_fn_ptr(Self::get_all);
        class.method(js_string!("get_all"), 0, get_all_fn);

        Ok(())
    }

    fn data_constructor(
        _new_target: &JsValue,
        _args: &[JsValue],
        _context: &mut JsContext,
    ) -> JsResult<Self> {
        let collection = MemorySetCollection::new();
        let collection: SetCollectionRef = Arc::new(Box::new(collection) as Box<dyn SetCollection>);
        Ok(Self::new(collection))
    }
}

#[derive(Clone, JsData, Finalize)]
pub struct MapCollectionWrapper {
    collection: MapCollectionRef,
}

impl MapCollectionWrapper {
    pub fn new(collection: MapCollectionRef) -> Self {
        Self { collection }
    }

    pub fn register(context: &mut JsContext) -> Result<(), String> {
        context.register_global_class::<Self>().map_err(|e| {
            let msg = format!("Failed to register MapCollectionWrapper: {}", e);
            error!("{}", msg);
            msg
        })
    }

    pub fn into_js_object(self, context: &mut JsContext) -> JsResult<JsObject> {
        // Get the prototype from the context registry
        let prototype = context
            .get_global_class::<SetCollectionWrapper>()
            .ok_or_else(|| {
                JsNativeError::error().with_message("SetCollectionWrapper prototype not found")
            })?
            .prototype();

        // Create a new JsObject with the prototype and data
        let js_obj = JsObject::from_proto_and_data(prototype, self);
        Ok(js_obj)
    }

    fn insert_new(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 arguments: key and value".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = CollectionWrapperHelper::js_value_to_collection_value(&args[1])?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.insert_new(&key, value)) {
            Ok(prev) => Ok(JsValue::Boolean(prev)),
            Err(e) => {
                let msg = format!("Failed to insert into map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn insert(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                let err = JsNativeError::error().with_message("Expected a string key");
                JsError::from(err)
            })?;

        let value = args.get(1).ok_or_else(|| {
            JsError::from(JsNativeError::error().with_message("Expected a value"))
        })?;

        let value = CollectionWrapperHelper::js_value_to_collection_value(value)?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.insert(&key, value)) {
            Ok(prev_value) => {
                // Convert previous value to JsValue
                let prev_js_value = match prev_value {
                    Some(v) => CollectionWrapperHelper::collection_value_to_js_value(v, context)?,
                    None => JsValue::Null,
                };

                Ok(prev_js_value)
            }
            Err(e) => {
                let msg = format!("Failed to insert into map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn get(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.get(&key)) {
            Ok(value) => match value {
                Some(v) => CollectionWrapperHelper::collection_value_to_js_value(v, context),
                None => Ok(JsValue::Null),
            },
            Err(e) => {
                let msg = format!("Failed to get from map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn contains_key(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.contains_key(&key)) {
            Ok(contains) => Ok(JsValue::Boolean(contains)),
            Err(e) => {
                let msg = format!("Failed to check if map contains key '{}': {}", key, e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn remove(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| {
                let err = JsNativeError::error().with_message("Expected a string key");
                JsError::from(err)
            })?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.remove(&key)) {
            Ok(prev_value) => {
                // Convert previous value to JsValue
                let prev_js_value = match prev_value {
                    Some(v) => CollectionWrapperHelper::collection_value_to_js_value(v, context)?,
                    None => JsValue::Null,
                };

                Ok(prev_js_value)
            }
            Err(e) => {
                let msg = format!("Failed to remove from map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }
}

unsafe impl Trace for MapCollectionWrapper {
    unsafe fn trace(&self, _tracer: &mut Tracer) {
        // No need to trace any JavaScript objects, as collection is Arc<dyn SetCollection>
        // Arc itself manages memory, garbage collector does not need to intervene
    }

    unsafe fn trace_non_roots(&self) {
        // No need to trace non-root objects, as there are no references to JavaScript objects
    }

    fn run_finalizer(&self) {
        // No special finalization needed, Arc will handle memory management
    }
}

impl Class for MapCollectionWrapper {
    const NAME: &'static str = "MapCollection";
    const LENGTH: usize = 0;

    fn init(class: &mut ClassBuilder) -> JsResult<()> {
        let insert_new_fn = NativeFunction::from_fn_ptr(Self::insert_new);
        class.method(js_string!("insert_new"), 2, insert_new_fn);

        let insert_fn = NativeFunction::from_fn_ptr(Self::insert);
        class.method(js_string!("insert"), 2, insert_fn);

        let get_fn = NativeFunction::from_fn_ptr(Self::get);
        class.method(js_string!("get"), 1, get_fn);

        let contains_fn = NativeFunction::from_fn_ptr(Self::contains_key);
        class.method(js_string!("contains_key"), 1, contains_fn);

        let remove_fn = NativeFunction::from_fn_ptr(Self::remove);
        class.method(js_string!("remove"), 1, remove_fn);

        Ok(())
    }

    fn data_constructor(
        _new_target: &JsValue,
        _args: &[JsValue],
        _context: &mut JsContext,
    ) -> JsResult<Self> {
        let collection = MemoryMapCollection::new();
        let collection: MapCollectionRef = Arc::new(Box::new(collection) as Box<dyn MapCollection>);
        Ok(Self::new(collection))
    }
}

#[derive(Clone, JsData, Finalize)]
pub struct MultiMapCollectionWrapper {
    collection: MultiMapCollectionRef,
}

impl MultiMapCollectionWrapper {
    pub fn new(collection: MultiMapCollectionRef) -> Self {
        Self { collection }
    }

    pub fn register(context: &mut JsContext) -> Result<(), String> {
        context.register_global_class::<Self>().map_err(|e| {
            let msg = format!("Failed to register MultiMapCollectionWrapper: {}", e);
            error!("{}", msg);
            msg
        })
    }

    pub fn into_js_object(self, context: &mut JsContext) -> JsResult<JsObject> {
        // Get the prototype from the context registry
        let prototype = context
            .get_global_class::<Self>()
            .ok_or_else(|| {
                JsNativeError::error().with_message("MultiMapCollectionWrapper prototype not found")
            })?
            .prototype();

        // Create a new JsObject with the prototype and data
        let js_obj = JsObject::from_proto_and_data(prototype, self);
        Ok(js_obj)
    }

    pub fn insert(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 arguments: key and value".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string value"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.insert(&key, &value)) {
            Ok(inserted) => Ok(JsValue::Boolean(inserted)),
            Err(e) => {
                let msg = format!("Failed to insert into multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn insert_many(
        this: &JsValue,
        args: &[JsValue],
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 arguments: key and value".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = CollectionWrapperHelper::js_value_to_string_list(&args[1], context)?;
        let value = value.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.insert_many(&key, &value)) {
            Ok(changed) => Ok(JsValue::Boolean(changed)),
            Err(e) => {
                let msg = format!("Failed to insert many into multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn get(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "Expected at least 1 argument: key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.get(&key)) {
            Ok(value) => match value {
                Some(v) => Ok(JsValue::String(JsString::from(v))),
                None => Ok(JsValue::Null),
            },
            Err(e) => {
                let msg = format!("Failed to get from multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    fn get_many(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.get_many(&key)) {
            Ok(ret) => match ret {
                Some(set) => {
                    let set = SetCollectionWrapper::new(set);
                    let value = set.into_js_object(context).map(JsValue::Object)?;
                    Ok(value)
                }
                None => Ok(JsValue::Null),
            },
            Err(e) => {
                let msg = format!("Failed to get from multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn contains_key(
        this: &JsValue,
        args: &[JsValue],
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "Expected at least 1 argument: key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.contains_key(&key)) {
            Ok(contains) => Ok(JsValue::Boolean(contains)),
            Err(e) => {
                let msg = format!("Failed to check if multi-map contains key '{}': {}", key, e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn contains_value(
        this: &JsValue,
        args: &[JsValue],
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 arguments: key and value".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = CollectionWrapperHelper::js_value_to_string_list(&args[1], context)?;
        let value = value.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.contains_value(&key, &value)) {
            Ok(contains) => Ok(JsValue::Boolean(contains)),
            Err(e) => {
                let msg = format!("Failed to check if multi-map contains value '{:?}': {}", value, e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn remove(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 argument: key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = args[0]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = args[1]
            .as_string()
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string value"))?;

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.remove(&key, &value)) {
            Ok(removed) => Ok(JsValue::Boolean(removed)),
            Err(e) => {
                let msg = format!("Failed to remove from multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn remove_many(
        this: &JsValue,
        args: &[JsValue],
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "Expected at least 2 argument: key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = if args[0].is_string() {
            args[0].as_string().unwrap().to_std_string_escaped()
        } else {
            let msg = "Expected a string key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        };

        let value = match CollectionWrapperHelper::js_value_to_string_list(&args[1], context) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Invalid value argument: {}", e);
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        let value = value.iter().map(|v| v.as_str()).collect::<Vec<&str>>();
        match rt.block_on(collection.remove_many(&key, &value)) {
            Ok(ret) => match ret {
                Some(values) => {
                    let set = SetCollectionWrapper::new(values);
                    let value = set.into_js_object(context).map(JsValue::Object)?;
                    Ok(value)
                }
                None => Ok(JsValue::Null),
            },
            Err(e) => {
                let msg = format!("Failed to remove all from multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }

    pub fn remove_all(
        this: &JsValue,
        args: &[JsValue],
        context: &mut JsContext,
    ) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MultiMapCollectionWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "Expected at least 1 argument: key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        let key = if args[0].is_string() {
            args[0].as_string().unwrap().to_std_string_escaped()
        } else {
            let msg = "Expected a string key".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(collection.remove_all(&key)) {
            Ok(ret) => match ret {
                Some(values) => {
                    let set = SetCollectionWrapper::new(values);
                    let value = set.into_js_object(context).map(JsValue::Object)?;
                    Ok(value)
                }
                None => Ok(JsValue::Null),
            },
            Err(e) => {
                let msg = format!("Failed to remove all from multi-map collection: {}", e);
                error!("{}", msg);
                Err(JsNativeError::error().with_message(msg).into())
            }
        }
    }
}

unsafe impl Trace for MultiMapCollectionWrapper {
    unsafe fn trace(&self, _tracer: &mut Tracer) {
        // No need to trace any JavaScript objects, as collection is Arc<dyn MultiMapCollection>
        // Arc itself manages memory, garbage collector does not need to intervene
    }

    unsafe fn trace_non_roots(&self) {
        // No need to trace non-root objects, as there are no references to JavaScript objects
    }

    fn run_finalizer(&self) {
        // No special finalization needed, Arc will handle memory management
    }
}

impl Class for MultiMapCollectionWrapper {
    const NAME: &'static str = "MultiMapCollection";
    const LENGTH: usize = 0;

    fn init(class: &mut ClassBuilder) -> JsResult<()> {
        let insert_fn = NativeFunction::from_fn_ptr(Self::insert);
        class.method(js_string!("insert"), 2, insert_fn);

        let insert_many_fn = NativeFunction::from_fn_ptr(Self::insert_many);
        class.method(js_string!("insert_many"), 2, insert_many_fn);

        let get_fn = NativeFunction::from_fn_ptr(Self::get);
        class.method(js_string!("get"), 1, get_fn);

        let get_many_fn = NativeFunction::from_fn_ptr(Self::get_many);
        class.method(js_string!("get_many"), 1, get_many_fn);

        let contains_key_fn = NativeFunction::from_fn_ptr(Self::contains_key);
        class.method(js_string!("contains_key"), 1, contains_key_fn);

        let contains_value_fn = NativeFunction::from_fn_ptr(Self::contains_value);
        class.method(js_string!("contains_value"), 2, contains_value_fn);

        let remove_fn = NativeFunction::from_fn_ptr(Self::remove);
        class.method(js_string!("remove"), 2, remove_fn);

        let remove_many_fn = NativeFunction::from_fn_ptr(Self::remove_many);
        class.method(js_string!("remove_many"), 2, remove_many_fn);

        let remove_all_fn = NativeFunction::from_fn_ptr(Self::remove_all);
        class.method(js_string!("remove_all"), 1, remove_all_fn);

        Ok(())
    }

    fn data_constructor(
        _new_target: &JsValue,
        _args: &[JsValue],
        _context: &mut JsContext,
    ) -> JsResult<Self> {
        let collection = MemoryMultiMapCollection::new();
        let collection: MultiMapCollectionRef =
            Arc::new(Box::new(collection) as Box<dyn MultiMapCollection>);
        Ok(Self::new(collection))
    }
}
