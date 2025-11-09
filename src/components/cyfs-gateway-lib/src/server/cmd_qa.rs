use crate::*;
use log::*;
use clap::{Arg, Command};
use cyfs_process_chain::{command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel, ExternalCommand, MapCollectionRef};

//impl process chain command : qa
// usage:
//   qa server_id [map_id]    if map_id is not provided, it will use REQ
//
// after qa execute, it will return the result as a map collection,store in ANSWER

const CMD_QA_NAME: &str = "qa";
pub struct CmdQa {
    cmd: Command,
    server_manager: ServerManagerRef,
}

impl CmdQa {
    pub fn new(server_manager: ServerManagerRef) -> Self {
        let cmd = Command::new(CMD_QA_NAME)
            .about("Call QA Server to answer questions")
            .after_help(
                r#"
Call a QA Server to answer questions based on the provided request data.

Usage:
  qa <server_id> [map_id]

Arguments:
  <server_id>   The ID of the QA server to call
  [map_id]      Optional. The ID of the map collection containing the question data.
                If not provided, defaults to "REQ"

Behavior:
  - Retrieves the specified map collection from the environment (defaults to $REQ)
  - Converts the map to JSON format
  - Calls the QA server's serve_question method
  - Stores the result in $ANSWER as a map collection

Examples:
  qa my_qa_server
  qa my_qa_server CUSTOM_REQ
  echo $ANSWER.result_code
"#,
            )
            .arg(Arg::new("server_id")
                .required(true)
                .index(1)
                .help("The ID of the QA server to call"))
            .arg(Arg::new("map_id")
                .required(false)
                .index(2)
                .help("The ID of the map collection containing the question (defaults to REQ)"));

        Self { 
            cmd,
            server_manager 
        }
    }

    pub fn name(&self) -> &str {
        CMD_QA_NAME
    }
}

#[async_trait::async_trait]
impl ExternalCommand for CmdQa {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid command arguments: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        _args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        // Parse arguments
        let matches = self.cmd
            .clone()
            .try_get_matches_from(origin_args.as_str_list())
            .map_err(|e| {
                let msg = format!("Failed to parse arguments: {}", e);
                error!("{}", msg);
                msg
            })?;

        let server_id = matches.get_one::<String>("server_id")
            .ok_or_else(|| {
                let msg = "server_id is required".to_string();
                error!("{}", msg);
                msg
            })?;

        let map_id = matches.get_one::<String>("map_id")
            .map(|s| s.as_str())
            .unwrap_or("REQ");

        info!("will execute qa command: server_id={}, map_id={}", server_id, map_id);

        // Get the QA server
        let server = self.server_manager.get_server(server_id)
            .ok_or_else(|| {
                let msg = format!("QA server '{}' not found", server_id);
                error!("{}", msg);
                msg
            })?;

        let qa_server = match server {
            Server::QA(qa_server) => qa_server,
            _ => {
                let msg = format!("Server '{}' is not a QA server", server_id);
                error!("{}", msg);
                return Err(msg);
            }
        };

        // Get the request map from environment
        let req_value = context.env().get(map_id, None).await?
            .ok_or_else(|| {
                let msg = format!("Map '{}' not found in environment", map_id);
                error!("{}", msg);
                msg
            })?;

        let req_map = req_value.as_map()
            .ok_or_else(|| {
                let msg = format!("'{}' is not a map collection", map_id);
                error!("{}", msg);
                msg
            })?;

        // Convert map to JSON using the trait
        let request_json = req_map.to_json().await
            .map_err(|e| {
                let msg = format!("Failed to convert map '{}' to JSON: {}", map_id, e);
                error!("{}", msg);
                msg.to_string()
            })?;

        info!("Calling QA server '{}' with request: {}", server_id, request_json);

        // Call QA server
        let response_json = qa_server.serve_question(&request_json).await
            .map_err(|e| {
                let msg = format!("QA server '{}' failed: {}", server_id, e);
                error!("{}", msg);
                msg
            })?;

        info!("QA server '{}' response: {}", server_id, response_json);

        // Convert response JSON to map using the trait
        let answer_map = MapCollectionRef::from_json(&response_json).await
            .map_err(|e| {
                let msg = format!("Failed to convert JSON response to map: {}", e);
                error!("{}", msg);
                msg.to_string()
            })?;

        // Store result in ANSWER
        context.env().create("ANSWER", CollectionValue::Map(answer_map), EnvLevel::Chain).await
            .map_err(|e| {
                let msg = format!("Failed to create ANSWER in environment: {}", e);
                error!("{}", msg);
                msg
            })?;

        info!("QA command completed successfully");
        Ok(CommandResult::success())
    }
}