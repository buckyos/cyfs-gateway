use crate::chain::{ProcessChainLibRef, ProcessChainRef};
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, RwLock};

pub const MAX_GOTO_COUNT: u32 = 128; // Maximum number of times the goto command can be executed in process chains execution

pub struct GotoCounter {
    pub count: AtomicU32, // The number of times the goto command has been executed
}

impl GotoCounter {
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    pub fn increment(&self) -> Result<(), String> {
        let prev = self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if prev >= MAX_GOTO_COUNT {
            let msg = format!(
                "Goto command has been executed {} times, exceeding the maximum limit of {}",
                prev + 1,
                MAX_GOTO_COUNT
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    pub fn get_count(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub type GotoCounterRef = Arc<GotoCounter>;

pub const MAX_STACK_DEPTH: usize = 64; // Maximum depth of the execution stack

enum ExecPointerInner {
    Lib(ProcessChainLibRef), // The library that this pointer is executing
    Chain(ProcessChainRef),  // The chain that this pointer is executing
    Block(String),           // The block id that this pointer is currently executing
}

impl ExecPointerInner {
    pub fn is_lib(&self) -> bool {
        matches!(self, ExecPointerInner::Lib(_))
    }

    pub fn is_chain(&self) -> bool {
        matches!(self, ExecPointerInner::Chain(_))
    }

    pub fn is_block(&self) -> bool {
        matches!(self, ExecPointerInner::Block(_))
    }

    pub fn into_lib(self) -> Option<ProcessChainLibRef> {
        if let ExecPointerInner::Lib(lib) = self {
            Some(lib)
        } else {
            None
        }
    }

    pub fn into_chain(self) -> Option<ProcessChainRef> {
        if let ExecPointerInner::Chain(chain) = self {
            Some(chain)
        } else {
            None
        }
    }

    pub fn into_block(self) -> Option<String> {
        if let ExecPointerInner::Block(block) = self {
            Some(block)
        } else {
            None
        }
    }
}

struct ExecPointerStack {
    stack: Vec<ExecPointerInner>, // Stack of execution pointers
}

impl ExecPointerStack {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn check_depth(&self) -> Result<(), String> {
        if self.depth() >= MAX_STACK_DEPTH {
            let msg = format!(
                "Execution stack depth {} exceeds maximum limit of {}",
                self.depth(),
                MAX_STACK_DEPTH
            );
            error!("{}", msg);
            return Err(msg);
        }

        Ok(())
    }

    pub fn push_lib(&mut self, lib: ProcessChainLibRef) {
        self.stack.push(ExecPointerInner::Lib(lib));
    }

    // The top item must be a lib, so we can safely unwrap
    pub fn pop_lib(&mut self) -> ProcessChainLibRef {
        self.stack
            .pop()
            .and_then(|item| item.into_lib())
            .expect("Expected the top of the stack to be a library")
    }

    pub fn push_chain(&mut self, chain: ProcessChainRef) {
        self.stack.push(ExecPointerInner::Chain(chain));
    }

    // The top item must be a chain, so we can safely unwrap
    pub fn pop_chain(&mut self) -> ProcessChainRef {
        self.stack
            .pop()
            .and_then(|item| item.into_chain())
            .expect("Expected the top of the stack to be a chain")
    }

    pub fn push_block(&mut self, block: String) {
        self.stack.push(ExecPointerInner::Block(block));
    }

    // The top item must be a block, so we can safely unwrap
    pub fn pop_block(&mut self) -> String {
        self.stack
            .pop()
            .and_then(|item| item.into_block())
            .expect("Expected the top of the stack to be a block")
    }

    pub fn current_lib(&self) -> Option<&ProcessChainLibRef> {
        // Search the stack from top to bottom for the first Lib
        for item in self.stack.iter().rev() {
            if let ExecPointerInner::Lib(lib) = item {
                return Some(lib);
            }
        }

        None
    }

    pub fn current_chain(&self) -> Option<&ProcessChainRef> {
        // Search the stack from top to bottom for the first Chain
        for item in self.stack.iter().rev() {
            if let ExecPointerInner::Chain(chain) = item {
                return Some(chain);
            }
        }

        None
    }

    pub fn current_block(&self) -> Option<&str> {
        // Search the stack from top to bottom for the first Block
        for item in self.stack.iter().rev() {
            if let ExecPointerInner::Block(block) = item {
                return Some(block.as_str());
            }
        }

        None
    }
}

#[derive(Clone)]
pub struct ExecPointer {
    stack: Arc<RwLock<ExecPointerStack>>, // The inner state of the execution pointer
}

impl ExecPointer {
    pub fn new() -> Self {
        Self {
            stack: Arc::new(RwLock::new(ExecPointerStack::new())),
        }
    }

    fn set_lib(&self, lib: ProcessChainLibRef) -> Result<(), String> {
        let mut stack = self.stack.write().unwrap();
        stack.check_depth()?;
        stack.push_lib(lib);

        Ok(())
    }

    fn reset_lib(&self) {
        let mut stack = self.stack.write().unwrap();
        stack.pop_lib();
    }

    fn set_chain(&self, chain: ProcessChainRef) -> Result<(), String> {
        let mut stack = self.stack.write().unwrap();
        stack.check_depth()?;
        stack.push_chain(chain);

        Ok(())
    }

    fn reset_chain(&self) {
        let mut stack = self.stack.write().unwrap();
        stack.pop_chain();
    }

    fn set_block(&self, block: &str) -> Result<(), String> {
        let mut stack = self.stack.write().unwrap();
        stack.check_depth()?;
        stack.push_block(block.to_string());

        Ok(())
    }

    fn reset_block(&self) {
        let mut stack = self.stack.write().unwrap();
        stack.pop_block();
    }

    // Get current executing library
    pub fn get_lib(&self) -> Option<ProcessChainLibRef> {
        let inner = self.stack.read().unwrap();
        inner.current_lib().cloned()
    }

    // Get current executing chain
    pub fn get_chain(&self) -> Option<ProcessChainRef> {
        let inner = self.stack.read().unwrap();
        inner.current_chain().cloned()
    }

    // Get current executing block
    pub fn get_block(&self) -> Option<String> {
        let inner = self.stack.read().unwrap();
        inner.current_block().map(|s| s.to_owned())
    }
}

pub struct ExecPointerLibGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerLibGuard<'a> {
    // Return value must be handled by caller
    #[must_use]
    pub fn new(pointer: &'a ExecPointer, lib: ProcessChainLibRef) -> Result<Self, String> {
        pointer.set_lib(lib)?;
        Ok(Self { pointer })
    }
}

impl<'a> Drop for ExecPointerLibGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_lib();
    }
}

pub struct ExecPointerChainGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerChainGuard<'a> {
    #[must_use]
    pub fn new(pointer: &'a ExecPointer, chain: ProcessChainRef) -> Result<Self, String> {
        pointer.set_chain(chain)?;
        Ok(Self { pointer })
    }
}

impl<'a> Drop for ExecPointerChainGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_chain();
    }
}

pub struct ExecPointerBlockGuard<'a> {
    pointer: &'a ExecPointer, // The execution pointer that this guard is managing
}

impl<'a> ExecPointerBlockGuard<'a> {
    #[must_use]
    pub fn new(pointer: &'a ExecPointer, block: &str) -> Result<Self, String> {
        pointer.set_block(block)?;
        Ok(Self { pointer })
    }
}

impl<'a> Drop for ExecPointerBlockGuard<'a> {
    fn drop(&mut self) {
        self.pointer.reset_block();
    }
}
