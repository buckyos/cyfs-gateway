use super::env_wrapper::EnvManagerWrapper;
use crate::chain::EnvManager;
use boa_engine::prelude::*;
use boa_engine::{
    Context as JsContext, JsResult, JsValue, NativeFunction, Trace,
    class::{Class, ClassBuilder},
    js_string,
};
use boa_gc::Tracer;

#[derive(Clone, JsData, Finalize)]
pub struct ContextWrapper {
    env_manager: EnvManager,
}

impl ContextWrapper {
    pub fn new(env_manager: EnvManager) -> Self {
        Self { env_manager }
    }

    pub fn register(context: &mut JsContext) -> Result<(), String> {
        context.register_global_class::<Self>().map_err(|e| {
            let msg = format!("Failed to register ContextWrapper: {}", e);
            error!("{}", msg);
            msg
        })
    }

    pub fn into_js_object(self, context: &mut JsContext) -> JsResult<JsObject> {
        // Get the prototype from the context registry
        let prototype = context
            .get_global_class::<Self>()
            .ok_or_else(|| {
                JsNativeError::error().with_message("ContextWrapper prototype not found")
            })?
            .prototype();

        // Create a new JsObject with the prototype and data
        let js_obj = JsObject::from_proto_and_data(prototype, self);
        Ok(js_obj)
    }

    pub fn env(this: &JsValue, _args: &[JsValue], context: &mut JsContext) -> JsResult<JsValue> {
        let this = this.as_object().and_then(|obj| obj.downcast_ref::<Self>());
        let wrapper = match &this {
            Some(this) => this,
            None => {
                let msg = format!("Failed to get EnvManagerWrapper from this");
                error!("{}", msg);
                return Err(JsNativeError::error().with_message(msg).into());
            }
        };

        let env = EnvManagerWrapper::new(wrapper.env_manager.clone());
        let obj = EnvManagerWrapper::into_js_object(env, context)?;
        Ok(obj.into())
    }
}

unsafe impl Trace for ContextWrapper {
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

impl Class for ContextWrapper {
    const NAME: &'static str = "Context";
    const LENGTH: usize = 0;

    fn init(class: &mut ClassBuilder) -> JsResult<()> {
        let env_fn = NativeFunction::from_fn_ptr(Self::env);
        class.method(js_string!("env"), 1, env_fn);

        Ok(())
    }

    fn data_constructor(
        _new_target: &JsValue,
        _args: &[JsValue],
        _context: &mut JsContext,
    ) -> JsResult<Self> {
        let msg = "Context cannot be constructed directly";
        error!("{}", msg);
        Err(JsNativeError::error().with_message(msg).into())
    }
}
