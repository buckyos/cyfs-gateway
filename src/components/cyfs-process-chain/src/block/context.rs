
use http_types::{headers::HeaderValue, Request, Response};
use super::storage::{HostStorageRef, new_memory_host_storage};
use std::str::FromStr;

// The environment in which the commands are executed
pub struct Context {
    req: Request,
    resp: Option<Response>,

    hosts: HostStorageRef,
}

impl Context {
    fn new() -> Self {
        let hosts = new_memory_host_storage();
        Self {
            req: Request::new(http_types::Method::Get, http_types::Url::parse("http://localhost").unwrap()),
            resp: None,
            hosts,
        }
    }

    pub fn get_value(&self, key: &str) -> Option<String> {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.is_empty() {
            warn!("Invalid key: {}", key);
            return None;
        }

        // Process cmd like REQ_HEADER.xxx, which will get header value from request
        match parts[0] {
            "REQ_HEADER" => {
                if parts.len() < 2 {
                    warn!("Invalid key: {}", key);
                    return None;
                }
                let header = self.req.header(parts[1]);
                if header.is_none() {
                    warn!("Header not found: {}", parts[1]);
                    return None;
                }
                Some(header.unwrap().as_str().to_string())
            }
            "RESP_HEADER" => {
                if parts.len() < 2 {
                    warn!("Invalid key: {}", key);
                    return None;
                }
                if self.resp.is_none() {
                    warn!("Response not set yet");
                    return None;
                }
                let header = self.resp.as_ref().unwrap().header(parts[1]);
                if header.is_none() {
                    warn!("Header not found: {}", parts[1]);
                    return None;
                }

                Some(header.unwrap().as_str().to_string())
            }
            _ => {
                warn!("Unknown key: {}", key);
                None
            }
        }
    }

    pub fn set_value(&mut self, key: &str, value: &str) -> Result<(), String> {
        let parts: Vec<&str> = key.split('.').collect();
        if parts.is_empty() {
            let msg = format!("Invalid key: {}", key);
            warn!("{}", msg);
            return Err(msg);
        }

        // Process cmd like REQ_HEADER.xxx, which will get header value from request
        match parts[0] {
            "REQ_HEADER" => {
                if parts.len() < 2 {
                    let msg = format!("Invalid key: {}", key);
                    warn!("{}", msg);
                    return Err(msg);
                }

                info!("Set header {} to {}", parts[1], value);
                self.req.insert_header(parts[1], value);

                Ok(())
            }
            "RESP_HEADER" => {
                if parts.len() < 2 {
                    let msg = format!("Invalid key: {}", key);
                    warn!("{}", msg);
                    return Err(msg);
                }

                if self.resp.is_none() {
                    let msg = "Response not set yet".to_string();
                    warn!("{}", msg);
                    return Err(msg);
                }

                self.resp.as_mut().unwrap().insert_header(parts[1], value);

                Ok(())
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    pub fn append_label(&mut self, label: &str) {
        if label.is_empty() {
            warn!("Empty label");
            return;
        }

        let value = self.req.header("label");
        if value.is_none() {
            self.req.insert_header("label", label);
            return;
        }

        let value = value.unwrap();
        self.req.insert_header("label", format!("{},{}", value, label));
    }

    // Reset label to a new value
    pub fn set_label(&mut self, label: &str) {
        if label.is_empty() {
            warn!("Empty label");
            return;
        }
        
        self.req.insert_header("label", label);
    }

    pub fn set_label_from_host_db(&mut self, host: &str) {
        // First load labels from storage
        let labels = self.hosts.get_labels(host);
        if labels.is_none() {
            warn!("Host not found: {}", host);
            return;
        }

        // Then set label to header label
        let labels = labels.unwrap();
        self.req.insert_header("label", labels);
    }

    pub fn is_label_set(&self, label: &str) -> bool {
        let value = self.req.header("label");
        if value.is_none() {
            return false;
        }

        let value = value.unwrap();

        let label = HeaderValue::from_str(label).unwrap();
        value.contains(&label)
    }
}