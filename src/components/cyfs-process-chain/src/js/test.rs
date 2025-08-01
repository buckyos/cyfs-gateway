use boa_engine::{
    js_class, Context, JsError, JsNativeFunction, JsObject, JsResult, JsValue,
    NativeFunction,
};
use std::rc::Rc;
use tokio::runtime::Runtime; // Assuming Tokio for async runtime

// 1. Define the Rust struct and async methods
struct MyRustClass {
    data: String,
}

impl MyRustClass {
    async fn fetch_data_async(&self, arg: String) -> Result<String, String> {
        // Simulate an async operation
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(format!("Fetched: {} - {}", self.data, arg))
    }
}

// 2. Implement JsClass for your Rust struct
#[js_class]
impl MyRustClass {
    #[boa_engine::constructor]
    fn new(_this: &JsObject, _args: &[JsValue], _context: &mut Context) -> JsResult<Self> {
        Ok(Self {
            data: "initial".to_string(),
        })
    }

    #[boa_engine::method]
    fn get_async_data(this: &JsObject, args: &[JsValue], context: &mut Context) -> JsResult<JsValue> {
        let instance = this.borrow::<MyRustClass>().unwrap();
        let arg = args.get(0).and_then(JsValue::as_string).map(|s| s.to_string()).unwrap_or_default();

        // 3. Wrap async method in JsNativeFunction and return a Promise
        let (promise, resolve, reject) = context.global_object().get("Promise", context)?.as_object().unwrap().new(&[], context)?.as_promise().unwrap().into_parts();

        let instance_data = instance.data.clone();
        let rt = Rc::new(Runtime::new().unwrap()); // Use a shared runtime

        let _ = rt.spawn(async move {
            match MyRustClass { data: instance_data }.fetch_data_async(arg).await {
                Ok(result) => {
                    let _ = resolve.call(&JsValue::undefined(), &[JsValue::from(result)], context);
                }
                Err(e) => {
                    let _ = reject.call(&JsValue::undefined(), &[JsValue::from(e)], context);
                }
            }
        });

        Ok(promise.into())
    }
}

// 4. Register the JsClass with Boa's Context
fn main() -> JsResult<()> {
    let mut context = Context::default();
    context.register_global_class::<MyRustClass>()?;

    let js_code = r#"
        let myInstance = new MyRustClass();
        myInstance.get_async_data("hello").then(result => {
            console.log(result); // Should log "Fetched: initial - hello"
        }).catch(err => {
            console.error(err);
        });
    "#;

    context.eval(boa_engine::Source::from_bytes(js_code))?;

    Ok(())
}