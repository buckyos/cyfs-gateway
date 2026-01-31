mod forward;
mod set_limit;
mod set_stat;
mod server;

use std::sync::Arc;
use cyfs_process_chain::{ExternalCommand, ExternalCommandRef, HttpProbeCommand, HttpsSniProbeCommand};
pub use forward::*;
pub use set_limit::*;
pub use set_stat::*;
pub use server::*;
use crate::{CmdQa, ServerManagerWeakRef};


pub fn get_external_commands(server_manager: ServerManagerWeakRef) -> Vec<(String, ExternalCommandRef)> {
    let mut cmds = vec![];

    let https_sni_probe_command = HttpsSniProbeCommand::new();
    let name = https_sni_probe_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(https_sni_probe_command) as Box<dyn ExternalCommand>)));

    let http_probe_command = HttpProbeCommand::new();
    let name = http_probe_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(http_probe_command) as Box<dyn ExternalCommand>)));

    let set_limit_command = SetLimit::new();
    let name = set_limit_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(set_limit_command) as Box<dyn ExternalCommand>)));

    let set_stat_command = SetStat::new();
    let name = set_stat_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(set_stat_command) as Box<dyn ExternalCommand>)));

    let forward_command = Forward::new();
    let name = forward_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(forward_command) as Box<dyn ExternalCommand>)));

    let server_command = CallServer::new();
    let name = server_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(server_command) as Box<dyn ExternalCommand>)));

    let qa_command = CmdQa::new(server_manager);
    let name = qa_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(qa_command) as Box<dyn ExternalCommand>)));

    cmds
}
