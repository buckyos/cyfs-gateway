use crate::StackProtocol;

pub trait Stack {
    fn stack_protocol(&self) -> StackProtocol;
    fn get_bind_addr(&self) -> String;
}
pub type StackBox = Box<dyn Stack>;

pub struct StackManager {
    stacks: Vec<StackBox>,
}

impl StackManager { 
    pub fn new() -> Self {
        Self {
            stacks: vec![],
        }
    }
}