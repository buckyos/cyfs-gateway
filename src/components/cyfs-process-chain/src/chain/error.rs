use super::Context;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessChainErrorCode {
    Unknown,
    ParseGeneral,
    LinkGeneral,
    RuntimeGeneral,
    RuntimeLineExecute,
    RuntimeStatementExecute,
    RuntimeExpressionExecute,
    RuntimeCommandExecute,
    RuntimeCommandNotLinked,
    EnvGeneral,
    CommandGeneral,
    ExternalGeneral,
}

impl ProcessChainErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessChainErrorCode::Unknown => "PC-UNKNOWN-0001",
            ProcessChainErrorCode::ParseGeneral => "PC-PARSE-0001",
            ProcessChainErrorCode::LinkGeneral => "PC-LINK-0001",
            ProcessChainErrorCode::RuntimeGeneral => "PC-RUNTIME-0001",
            ProcessChainErrorCode::RuntimeLineExecute => "PC-RUNTIME-0101",
            ProcessChainErrorCode::RuntimeStatementExecute => "PC-RUNTIME-0102",
            ProcessChainErrorCode::RuntimeExpressionExecute => "PC-RUNTIME-0103",
            ProcessChainErrorCode::RuntimeCommandExecute => "PC-RUNTIME-0104",
            ProcessChainErrorCode::RuntimeCommandNotLinked => "PC-RUNTIME-0105",
            ProcessChainErrorCode::EnvGeneral => "PC-ENV-0001",
            ProcessChainErrorCode::CommandGeneral => "PC-CMD-0001",
            ProcessChainErrorCode::ExternalGeneral => "PC-EXTERNAL-0001",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorLocation {
    pub lib: Option<String>,
    pub chain: Option<String>,
    pub block: Option<String>,
    pub line: Option<usize>,
    pub source: Option<String>,
    pub command: Option<String>,
}

impl ErrorLocation {
    pub fn from_context(context: &Context) -> Self {
        let pointer = context.current_pointer();

        let lib = pointer.get_lib().map(|lib| lib.get_id().to_string());
        let chain = pointer.get_chain().map(|chain| chain.id().to_string());
        let block = pointer.get_block();

        Self {
            lib,
            chain,
            block,
            line: None,
            source: None,
            command: None,
        }
    }

    pub fn with_line_source(mut self, line: usize, source: &str) -> Self {
        self.line = Some(line);
        self.source = Some(source.to_string());
        self
    }

    pub fn with_command(mut self, command: &str) -> Self {
        self.command = Some(command.to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessChainError {
    pub code: ProcessChainErrorCode,
    pub message: String,
    pub location: ErrorLocation,
    pub cause: Option<String>,
}

impl ProcessChainError {
    pub fn new(code: ProcessChainErrorCode, message: impl Into<String>, context: &Context) -> Self {
        Self {
            code,
            message: message.into(),
            location: ErrorLocation::from_context(context),
            cause: None,
        }
    }

    pub fn with_location(mut self, location: ErrorLocation) -> Self {
        self.location = location;
        self
    }

    pub fn with_line_source(mut self, line: usize, source: &str) -> Self {
        self.location = self.location.with_line_source(line, source);
        self
    }

    pub fn with_command(mut self, command: &str) -> Self {
        self.location = self.location.with_command(command);
        self
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }
}

impl Display for ProcessChainError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let lib = self.location.lib.as_deref().unwrap_or("-");
        let chain = self.location.chain.as_deref().unwrap_or("-");
        let block = self.location.block.as_deref().unwrap_or("-");
        let line = self
            .location
            .line
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let source = self
            .location
            .source
            .as_deref()
            .unwrap_or("-")
            .replace('\n', "\\n");
        let command = self.location.command.as_deref().unwrap_or("-");

        write!(
            f,
            "[{}] {} | lib={} chain={} block={} line={} source={} command={}",
            self.code.as_str(),
            self.message,
            lib,
            chain,
            block,
            line,
            source,
            command
        )?;

        if let Some(cause) = &self.cause {
            write!(f, " | cause={}", cause.replace('\n', "\\n"))?;
        }

        Ok(())
    }
}
