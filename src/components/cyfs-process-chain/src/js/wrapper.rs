use crate::collection::{self, *};
use boa_engine::{
    Context as JsContext, Finalize, JsData, JsError, JsNativeError, JsObject, JsResult, JsString,
    JsValue, NativeFunction, Trace,
    builtins::promise::PromiseState,
    class::{Class, ClassBuilder},
    job::{JobQueue, NativeJob},
    js_string,
    object::{
        Object,
        builtins::{JsArray, JsPromise},
    },
};
use boa_gc::Tracer;
use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(Clone, JsData, Finalize)]
pub struct SetCollectionWrapper {
    collection: SetCollectionRef,
}

fn insert1(
    this: &JsValue,
    args: &[JsValue],
    _context: &mut JsContext,
) -> impl Future<Output = JsResult<JsValue>> {
    let arg = args.get(0).cloned();
         async move {
             std::future::ready(()).await;
             drop(arg);
         Ok(JsValue::null())
     }
}

impl SetCollectionWrapper {
    pub fn new(collection: SetCollectionRef) -> Self {
        Self { collection }
    }

    fn create(_this: &JsValue, _args: &[JsValue], context: &mut JsContext) -> JsObject {
        use boa_engine::object::ObjectInitializer;

        ObjectInitializer::new(context)
            .function(
                NativeFunction::from_async_fn(insert1),
                js_string!("insert1"),
                1,
            )
            .build()
    }

    fn insert(
        this: &JsValue,
        args: &[JsValue],
        _context: &mut JsContext,
    ) -> BoxFuture<'static, JsResult<JsValue>> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let value = args
            .get(0)
            .map(|v| {
                v.as_string()
                    .map(|s| s.to_std_string_escaped())
                    .ok_or_else(|| "Expected a string value")
            })
            .unwrap_or_else(|| Err("No value provided"));
        let value = match value {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Invalid argument: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let ft = async move {
            //let this = this?;
            collection
                .insert(&value)
                .await
                .map(|inserted| JsValue::Boolean(inserted))
                .map_err(|e| JsError::from_native(JsNativeError::error().with_message(e)))
        };

        Box::pin(ft)
    }

    fn contains(
        this: &JsValue,
        args: &[JsValue],
        _context: &mut JsContext,
    ) -> BoxFuture<'static, JsResult<JsValue>> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"));
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Invalid argument: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let ft = async move {
            collection
                .contains(&key)
                .await
                .map(JsValue::Boolean)
                .map_err(|e| JsError::from_native(JsNativeError::error().with_message(e)))
        };

        Box::pin(ft)
    }

    fn remove(
        this: &JsValue,
        args: &[JsValue],
        _context: &mut JsContext,
    ) -> BoxFuture<'static, JsResult<JsValue>> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get SetCollectionWrapper from this");
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"));
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Invalid argument: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let ft = async move {
            collection
                .remove(&key)
                .await
                .map(|removed| JsValue::Boolean(removed))
                .map_err(|e| JsError::from_native(JsNativeError::error().with_message(e)))
        };

        Box::pin(ft)
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

        let rt = Runtime::new().map_err(|e| JsNativeError::error().with_message(e.to_string()))?;

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
        //let insert1 = NativeFunction::from_async_fn(Self::insert1);
        //class.method(js_string!("insert1"), 1, insert1);

        let insert_fn = NativeFunction::from_async_fn(Self::insert);
        class.method(js_string!("insert"), 1, insert_fn);

        let contains_fn = NativeFunction::from_async_fn(Self::contains);
        class.method(js_string!("contains"), 1, contains_fn);

        let remove_fn = NativeFunction::from_async_fn(Self::remove);
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

/*
#[derive(Clone, JsData, Finalize)]
pub struct MapCollectionWrapper {
    collection: MapCollectionRef,
}

impl MapCollectionWrapper {
    pub fn new(collection: MapCollectionRef) -> Self {
        Self { collection }
    }

    fn insert(
        this: &JsValue,
        args: &[JsValue],
        _context: &mut JsContext,
    ) -> BoxFuture<'static, JsResult<JsValue>> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"));
        let value = args
            .get(1)
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string value"));

        let key = match key {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Invalid argument for key: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };
        let value = match value {
            Ok(v) => {
                if v.is_string() {
                    let s = v
                        .as_string()
                        .map(|s| s.to_std_string_escaped())
                        .ok_or_else(|| "Expected a string value");

                    match s {
                        Ok(s) => CollectionValue::String(s),
                        Err(e) => {
                            let msg = format!("Invalid argument for value: {}", e);
                            error!("{}", msg);
                            return Box::pin(async {
                                Err(JsNativeError::error().with_message(msg).into())
                            });
                        }
                    }
                } else if v.is_object() {
                    let obj = v.as_object().ok_or_else(|| "Expected an object value");
                    let obj = match obj {
                        Ok(o) => o,
                        Err(e) => {
                            let msg = format!("Invalid argument for value: {}", e);
                            error!("{}", msg);
                            return Box::pin(async {
                                Err(JsNativeError::error().with_message(msg).into())
                            });
                        }
                    };

                    // Check if the object is a valid CollectionValue
                    if let Some(coll_value) = obj.downcast_ref::<SetCollectionWrapper>() {
                        CollectionValue::Set(Arc::clone(&coll_value.collection))
                    } else if let Some(map_value) = obj.downcast_ref::<MapCollectionWrapper>() {
                        CollectionValue::Map(Arc::clone(&map_value.collection))
                    } else {
                        let msg = "Expected a valid CollectionValue object".to_string();
                        error!("{}", msg);
                        return Box::pin(async {
                            Err(JsNativeError::error().with_message(msg).into())
                        });
                    }
                } else {
                    let msg = "Expected a string or object value".to_string();
                    error!("{}", msg);
                    return Box::pin(async {
                        Err(JsNativeError::error().with_message(msg).into())
                    });
                }
            }
            Err(e) => {
                let msg = format!("Invalid argument for value: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        JsObject::from_proto_and_data(prototype, data)
                let ft = async move {
            collection
                .insert(&key, value)
                .await
                .map(|prev| match prev {
                    Some(prev_value) => match prev_value {
                        CollectionValue::String(s) => (JsValue::String(JsString::from(s))),
                        CollectionValue::Map(map) => JsValue::from(MapCollectionWrapper::new(map)),
                        CollectionValue::Set(set) => JsValue::from(SetCollectionWrapper::new(set)),
                        _ => JsValue::Null,
                    },
                    None => JsValue::Null,
                })
                .map_err(|e| JsError::from_native(JsNativeError::error().with_message(e)))
        };

        Box::pin(ft)
    }

    fn contains(
        this: &JsValue,
        args: &[JsValue],
        _context: &mut JsContext,
    ) -> BoxFuture<'static, JsResult<JsValue>> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let collection = match this {
            Some(this) => this.collection.clone(),
            None => {
                let msg = format!("Failed to get MapCollectionWrapper from this");
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"));
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                let msg = format!("Invalid argument: {}", e);
                error!("{}", msg);
                return Box::pin(async { Err(JsNativeError::error().with_message(msg).into()) });
            }
        };

        let ft = async move {
            collection
                .contains_key(&key)
                .await
                .map(JsValue::Boolean)
                .map_err(|e| JsError::from_native(JsNativeError::error().with_message(e)))
        };

        Box::pin(ft)
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
        let insert_fn = NativeFunction::from_async_fn(Self::insert);
        class.method(js_string!("insert"), 2, insert_fn);

        let contains_fn = NativeFunction::from_async_fn(Self::contains);
        class.method(js_string!("contains"), 1, contains_fn);

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

*/
