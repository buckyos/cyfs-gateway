use http_types::{Request, Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestItemType {
    // Use for write indeed
    Normal,

    // Use for virtual write(assign)
    Virtual,
}

pub struct RequestItem {
    pub type_: RequestItemType,
    pub req: Request,
    pub resp: Option<Response>,
}

impl RequestItem {
    pub fn new(req: Request, resp: Option<Response>) -> Self {
        Self {
            type_: RequestItemType::Normal,
            req,
            resp,
        }
    }

    pub fn fork_virtual(&self) -> Self {
        Self {
            type_: RequestItemType::Virtual,
            req: Request::new(self.req.method().clone(), self.req.url().clone()),
            resp: self.resp.as_ref().map(|r| Response::new(r.status())),
        }
    }

    pub fn get_method(&self) -> http_types::Method {
        self.req.method()
    }

    pub fn set_method(&mut self, method: http_types::Method) {
        if self.req.method() == method {
            return;
        }

        info!(
            "Method changed from {} to {}",
            self.req.method(),
            method
        );
        self.req.set_method(method);
    }

    // Header related
    pub fn get_header(&self, key: &str) -> Option<&str> {
        self.req.header(key).map(|h| h.as_str())
    }

    pub fn set_header(&mut self, key: &str, value: &str) {
        if let Some(prev) = self.req.insert_header(key, value) {
            info!(
                "Header {} already exists, will be replaced, old value: {}",
                key, prev
            );
        } else {
            debug!("Set header {} to value {}", key, value);
        }
    }

    pub fn append_header(&mut self, key: &str, value: &str) {
        self.req.append_header(key, value);
         
        debug!("Append header {} with value {}", key, value);
    }

    pub fn get_resp_header(&self, key: &str) -> Option<&str> {
        self.resp
            .as_ref()
            .and_then(|r| r.header(key))
            .map(|h| h.as_str())
    }

    pub fn set_resp_header(&mut self, key: &str, value: &str) -> Result<(), String> {
        if self.resp.is_none() {
            let msg = "Response not set yet".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        if let Some(prev) = self.resp.as_mut().unwrap().insert_header(key, value) {
            info!(
                "Response header {} already exists, will be replaced, old value: {}",
                key, prev
            );
        } else {
            debug!("Set response header {} to value {}", key, value);
        }

        Ok(())
    }

    // Body related
    pub fn get_content_type(&self) -> Option<String> {
        self.req.content_type().map(|c| c.to_string())
    }
}
