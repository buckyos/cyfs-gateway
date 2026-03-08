mod error;
mod forward;
mod in_time_range;
mod num_cmp;
mod proxy_protocol_probe;
mod redirect;
mod set_limit;
mod set_stat;
mod server;

use std::sync::Arc;
use cyfs_process_chain::{ExternalCommand, ExternalCommandRef, HttpProbeCommand, HttpsSniProbeCommand};
pub use error::*;
pub use forward::*;
pub use in_time_range::*;
pub use num_cmp::*;
pub use proxy_protocol_probe::*;
pub use redirect::*;
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

    let proxy_protocol_probe = ProxyProtocolProbeCommand::new();
    let name = proxy_protocol_probe.name().to_owned();
    cmds.push((name, Arc::new(Box::new(proxy_protocol_probe) as Box<dyn ExternalCommand>)));

    let set_limit_command = SetLimit::new();
    let name = set_limit_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(set_limit_command) as Box<dyn ExternalCommand>)));

    let set_stat_command = SetStat::new();
    let name = set_stat_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(set_stat_command) as Box<dyn ExternalCommand>)));

    let error_command = ErrorResponse::new();
    let name = error_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(error_command) as Box<dyn ExternalCommand>)));

    let forward_command = Forward::new();
    let name = forward_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(forward_command) as Box<dyn ExternalCommand>)));

    let redirect_command = Redirect::new();
    let name = redirect_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(redirect_command) as Box<dyn ExternalCommand>)));

    let in_time_range_command = InTimeRange::new();
    let name = in_time_range_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(in_time_range_command) as Box<dyn ExternalCommand>)));

    let num_cmp_command = NumCmp::new();
    let name = num_cmp_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(num_cmp_command) as Box<dyn ExternalCommand>)));

    let server_command = CallServer::new();
    let name = server_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(server_command) as Box<dyn ExternalCommand>)));

    let qa_command = CmdQa::new(server_manager);
    let name = qa_command.name().to_owned();
    cmds.push((name, Arc::new(Box::new(qa_command) as Box<dyn ExternalCommand>)));

    cmds
}
