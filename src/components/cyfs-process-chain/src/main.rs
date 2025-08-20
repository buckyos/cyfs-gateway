#![allow(dead_code)]

#[macro_use]
extern crate log;

mod block;
mod chain;
mod cmd;
mod collection;
mod js;
mod hook_point;
mod http;
mod pipe;
mod repl;
mod tcp;

#[cfg(test)]
mod test;

pub use block::*;
pub use chain::*;
pub use cmd::*;
pub use collection::*;
pub use hook_point::*;
pub use http::*;
pub use pipe::*;
pub use tcp::*;

use repl::*;

#[tokio::main]
async fn main() {
    // Initialize logging
    simplelog::SimpleLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default())
        .unwrap();

    let ret = ProcessChainREPL::new().await;
    let repl = match ret {
        Ok(repl) => repl,
        Err(e) => {
            eprintln!("Failed to create REPL: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = repl.init().await {
        eprintln!("Failed to initialize REPL: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = repl.run().await {
        eprintln!("REPL encountered an error: {}", e);
        std::process::exit(1);
    }
}
