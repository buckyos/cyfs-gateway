use std::sync::Arc;

use cyfs_process_chain::{ExternalCommandFactory, ExternalCommandRef};

use crate::{config_err, ConfigErrorCode, ConfigResult};

#[derive(Clone)]
pub struct JsExternalsManager {
    command_factory: ExternalCommandFactory,
}

pub type JsExternalsManagerRef = Arc<JsExternalsManager>;

impl JsExternalsManager {
    pub fn new() -> Self {
        Self {
            command_factory: ExternalCommandFactory::new(),
        }
    }

    pub async fn add_js_external(&self, name: &str, source: String) -> ConfigResult<()> {
        self.command_factory
            .register_js_external_command(name, source)
            .await
            .map_err(|e| {
                config_err!(
                    ConfigErrorCode::InvalidConfig,
                    "register js external command '{}' failed: {}",
                    name,
                    e
                )
            })
    }

    pub fn get_external_commands(&self) -> Vec<(String, ExternalCommandRef)> {
        let mut command_names = self.command_factory.get_command_list();
        command_names.sort();

        let mut commands = Vec::new();
        for name in command_names {
            if let Some(command) = self.command_factory.get_command(name.as_str()) {
                commands.push((name, command));
            }
        }

        commands
    }
}
