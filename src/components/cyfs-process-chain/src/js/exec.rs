use super::coll_wrapper::CollectionWrapperHelper;
use crate::CommandResult;
use crate::collection::CollectionValue;
use boa_engine::{Context as JsContext, JsObject, JsValue, Source, js_string, property::Attribute};
use boa_runtime::Console;
use std::error::Error;
use std::sync::{Arc, Mutex};

pub struct JavaScriptExecutor {
    context: Arc<Mutex<JsContext>>,
}

impl JavaScriptExecutor {
    pub fn new() -> Result<Self, String> {
        let mut context = JsContext::default();

        // Register console object
        let console = Console::init(&mut context);

        // Register the console as a global property to the context.
        context
            .register_global_property(js_string!(Console::NAME), console, Attribute::all())
            .map_err(|e| {
                let msg = format!("Failed to register console: {}", e);
                error!("{}", msg);
                msg
            })?;

        let context = Arc::new(Mutex::new(context));

        Ok(Self { context })
    }

    pub fn context(&self) -> &Arc<Mutex<JsContext>> {
        &self.context
    }

    // Evaluate the PAC script
    fn load(&self, src: &str) -> Result<(), String> {
        let mut context = self.context.lock().unwrap();

        let src = Source::from_bytes(src.as_bytes());
        context.eval(src).map_err(|e| {
            let mut source = e.source();
            while let Some(err) = source {
                println!("Caused by: {:?}", err);
                source = err.source();
            }

            let msg = format!("failed to eval js script: {:?}, {:?}", e, e.source());
            error!("{}", msg);
            msg
        })?;

        Ok(())
    }
}

pub struct JavaScriptFunctionCaller {
    name: String,
    caller: Arc<Mutex<JsObject>>,
}

impl JavaScriptFunctionCaller {
    pub fn load(name: &str, context: &mut JsContext) -> Result<Self, String> {
        let func = context
            .global_object()
            .get(js_string!(name), context)
            .map_err(|e| {
                let msg = format!("failed to get function: {}, {:?}", name, e);
                error!("{}", msg);
                msg
            })?;

        // Check if the {name} is a not none and a function
        if func.is_null_or_undefined() {
            let msg = format!("{} is not defined yet!", name);
            error!("{}", msg);
            return Err(msg);
        }

        let func = func.as_callable().ok_or_else(|| {
            let msg = format!("{} is not a callable function!", name);
            error!("{}", msg);
            msg
        })?;

        let ret = Self {
            name: name.to_string(),
            caller: Arc::new(Mutex::new(func.clone())),
        };

        Ok(ret)
    }

    pub fn call(
        &self,
        context: &mut JsContext,
        args: Vec<CollectionValue>,
    ) -> Result<CommandResult, String> {
        // Convert args to JsValue
        let mut js_args: Vec<_> = Vec::with_capacity(args.len());
        for arg in args {
            let js_value = CollectionWrapperHelper::collection_value_to_js_value(arg, context)
                .map_err(|e| {
                    let msg = format!("Failed to convert argument to JsValue: {:?}", e);
                    error!("{}", msg);
                    msg
                })?;

            js_args.push(js_value);
        }

        let caller = self.caller.lock().unwrap();
        // Call the function
        let result = caller
            .call(&JsValue::undefined(), &js_args, context)
            .map_err(|e| {
                let msg = format!("Failed to call function {}: {:?}", self.name, e);
                error!("{}", msg);
                msg
            })?;

        /*
        return {
            state: bool,
            result: CollectionValue,
        };
         */
        let return_object = result.as_object().ok_or_else(|| {
            let msg = format!("Function {} did not return an object", self.name);
            error!("{}", msg);
            msg
        })?;

        // Get the state and result from the return object
        let state = return_object
            .get(js_string!("state"), context)
            .map_err(|e| {
                let msg = format!("Failed to get 'state' from return object: {:?}", e);
                error!("{}", msg);
                msg
            })?
            .as_boolean()
            .ok_or_else(|| {
                let msg = format!("'state' is not a boolean in return object");
                error!("{}", msg);
                msg
            })?;

        let value: JsValue = return_object
            .get(js_string!("result"), context)
            .map_err(|e| {
                let msg = format!("Failed to get 'result' from return object: {:?}", e);
                error!("{}", msg);
                msg
            })?;
        let value = CollectionWrapperHelper::js_value_to_collection_value(&value).map_err(|e| {
            let msg = format!("Failed to convert result to CollectionValue: {:?}", e);
            error!("{}", msg);
            msg
        })?;

        let ret = match state {
            true => CommandResult::success_with_value(value.treat_as_str()),
            false => CommandResult::error_with_value(value.treat_as_str()),
        };

        Ok(ret)
    }
}
