use super::coll_wrapper::CollectionWrapperHelper;
use super::exec::RuntimeHandleWrapper;
use crate::EnvLevel;
use crate::chain::EnvManager;
use boa_engine::prelude::*;
use boa_engine::{
    Context as JsContext, JsResult, JsValue, NativeFunction, Trace,
    class::{Class, ClassBuilder},
    js_string,
};
use boa_gc::Tracer;
use std::str::FromStr;

#[derive(Clone, JsData, Finalize)]
pub struct EnvManagerWrapper {
    env_manager: EnvManager,
}

impl EnvManagerWrapper {
    pub fn new(env_manager: EnvManager) -> Self {
        Self { env_manager }
    }

    pub fn register(context: &mut JsContext) -> Result<(), String> {
        context.register_global_class::<Self>().map_err(|e| {
            let msg = format!("Failed to register EnvManagerWrapper: {}", e);
            error!("{}", msg);
            msg
        })
    }

    pub fn into_js_object(self, context: &mut JsContext) -> JsResult<JsObject> {
        // Get the prototype from the context registry
        let prototype = context
            .get_global_class::<Self>()
            .ok_or_else(|| {
                JsNativeError::error().with_message("SetCollectionWrapper prototype not found")
            })?
            .prototype();

        // Create a new JsObject with the prototype and data
        let js_obj = JsObject::from_proto_and_data(prototype, self);
        Ok(js_obj)
    }

    pub fn create(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let obj = this.as_object().ok_or_else(|| {
            let msg = "Expected this to be an object".to_string();
            error!("{}", msg);
            JsNativeError::error().with_message(msg)
        })?;
        let this = obj.downcast_ref::<Self>();
        let env_manager = match this {
            Some(this) => this.env_manager.clone(),
            None => {
                let msg = format!("Failed to get EnvManagerWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "EnvManagerWrapper.create requires at least 2 arguments".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        // Get first argument as key
        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = CollectionWrapperHelper::js_value_to_collection_value(&args[1])?;

        let env_level = if args.len() > 2 {
            let level = args
                .get(0)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .ok_or_else(|| JsNativeError::error().with_message("Expected a string level"))?;

            match EnvLevel::from_str(&level) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid environment level: {}", e);
                    error!("{}", msg);
                    return Err(JsNativeError::error().with_message(msg).into());
                }
            }
        } else {
            EnvLevel::default()
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(env_manager.create(&key, value, env_level)) {
            Ok(ret) => Ok(JsValue::from(ret)),
            Err(e) => Err(JsNativeError::error().with_message(e).into()),
        }
    }

    pub fn set(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        info!("Calling EnvManagerWrapper.set");
        let obj = this.as_object().ok_or_else(|| {
            let msg = "Expected this to be an object".to_string();
            error!("{}", msg);
            JsNativeError::error().with_message(msg)
        })?;
        let this = obj.downcast_ref::<Self>();
        let env_manager = match this {
            Some(this) => this.env_manager.clone(),
            None => {
                let msg = format!("Failed to get EnvManagerWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.len() < 2 {
            let msg = "EnvManagerWrapper.set requires at least 2 arguments".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        // Get first argument as key
        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let value = CollectionWrapperHelper::js_value_to_collection_value(&args[1])?;

        let env_level = if args.len() > 2 {
            let level = args
                .get(2)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .ok_or_else(|| {
                    JsNativeError::error().with_message("Expected a string env level")
                })?;

            let level = match EnvLevel::from_str(&level) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid environment level: {}", e);
                    error!("{}", msg);
                    return Err(JsNativeError::error().with_message(msg).into());
                }
            };
            Some(level)
        } else {
            None
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(env_manager.set(&key, value, env_level)) {
            Ok(Some(v)) => CollectionWrapperHelper::collection_value_to_js_value(v, context),
            Ok(None) => Ok(JsValue::null()),
            Err(e) => Err(JsNativeError::error().with_message(e).into()),
        }
    }

    pub fn get(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let obj = this.as_object().ok_or_else(|| {
            let msg = "Expected this to be an object".to_string();
            error!("{}", msg);
            JsNativeError::error().with_message(msg)
        })?;
        let this = obj.downcast_ref::<Self>();
        let env_manager = match this {
            Some(this) => this.env_manager.clone(),
            None => {
                let msg = format!("Failed to get EnvManagerWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "EnvManagerWrapper.get requires at least 1 argument".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        // Get first argument as key
        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let env_level = if args.len() > 1 {
            let level = args
                .get(1)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .ok_or_else(|| {
                    JsNativeError::error().with_message("Expected a string env level")
                })?;

            let level = match EnvLevel::from_str(&level) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid environment level: {}", e);
                    error!("{}", msg);
                    return Err(JsNativeError::error().with_message(msg).into());
                }
            };

            Some(level)
        } else {
            None
        };

        info!(
            "Getting value for key: {} with env level: {:?}",
            key, env_level
        );

        let runtime_handle = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match runtime_handle.block_on(env_manager.get(&key, env_level)) {
            Ok(Some(v)) => CollectionWrapperHelper::collection_value_to_js_value(v, context),
            Ok(None) => Ok(JsValue::null()),
            Err(e) => Err(JsNativeError::error().with_message(e).into()),
        }
    }

    pub fn remove(this: &JsValue, args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let obj = this.as_object().ok_or_else(|| {
            let msg = "Expected this to be an object".to_string();
            error!("{}", msg);
            JsNativeError::error().with_message(msg)
        })?;
        let this = obj.downcast_ref::<Self>();
        let env_manager = match this {
            Some(this) => this.env_manager.clone(),
            None => {
                let msg = format!("Failed to get EnvManagerWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        if args.is_empty() {
            let msg = "EnvManagerWrapper.remove requires at least 1 argument".to_string();
            error!("{}", msg);
            return Err(JsNativeError::error().with_message(msg).into());
        }

        // Get first argument as key
        let key = args
            .get(0)
            .and_then(|v| v.as_string())
            .map(|s| s.to_std_string_escaped())
            .ok_or_else(|| JsNativeError::error().with_message("Expected a string key"))?;

        let env_level = if args.len() > 1 {
            let level = args
                .get(1)
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .ok_or_else(|| {
                    JsNativeError::error().with_message("Expected a string env level")
                })?;

            let level = match EnvLevel::from_str(&level) {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Invalid environment level: {}", e);
                    error!("{}", msg);
                    return Err(JsNativeError::error().with_message(msg).into());
                }
            };

            Some(level)
        } else {
            None
        };

        let rt = context.get_data::<RuntimeHandleWrapper>().unwrap();
        match rt.block_on(env_manager.remove(&key, env_level)) {
            Ok(Some(v)) => CollectionWrapperHelper::collection_value_to_js_value(v, context),
            Ok(None) => Ok(JsValue::null()),
            Err(e) => Err(JsNativeError::error().with_message(e).into()),
        }
    }
}

unsafe impl Trace for EnvManagerWrapper {
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

impl Class for EnvManagerWrapper {
    const NAME: &'static str = "EnvManager";
    const LENGTH: usize = 0;

    fn init(class: &mut ClassBuilder) -> JsResult<()> {
        let create_fn = NativeFunction::from_fn_ptr(Self::create);
        class.method(js_string!("create"), 1, create_fn);

        let set_fn = NativeFunction::from_fn_ptr(Self::set);
        class.method(js_string!("set"), 2, set_fn);

        let get_fn = NativeFunction::from_fn_ptr(Self::get);
        class.method(js_string!("get"), 1, get_fn);

        let remove_fn = NativeFunction::from_fn_ptr(Self::remove);
        class.method(js_string!("remove"), 1, remove_fn);

        Ok(())
    }

    fn data_constructor(
        _new_target: &JsValue,
        _args: &[JsValue],
        _context: &mut JsContext,
    ) -> JsResult<Self> {
        let msg = "EnvManager cannot be constructed directly";
        error!("{}", msg);
        Err(JsNativeError::error().with_message(msg).into())
    }
}
