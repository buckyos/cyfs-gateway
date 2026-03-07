use cyfs_process_chain::{
    Block, CommandArg, Expression, ExpressionChain, IfStatement, ProcessChain,
    ProcessChainJSONLoader, ProcessChainXMLLoader, Statement,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LintSeverity {
    Error,
    Warning,
    Info,
}

impl LintSeverity {
    pub fn rank(self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 2,
            Self::Info => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: LintSeverity,
    pub message: String,
    pub file: String,
    pub lib: String,
    pub chain: String,
    pub block: String,
    pub line: usize,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct LintConfig {
    pub known_vars: HashSet<String>,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            known_vars: default_known_vars(),
        }
    }
}

pub fn default_known_vars() -> HashSet<String> {
    [
        "REQ",
        "REQ_HEADER",
        "REQ_URL",
        "__args",
        "__key",
        "__value",
        "__index",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn lint_file(path: &Path, config: &LintConfig) -> Result<Vec<Diagnostic>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read '{}': {}", path.display(), e))?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

    let chains = if ext.eq_ignore_ascii_case("json") {
        ProcessChainJSONLoader::parse(&content)?
    } else {
        ProcessChainXMLLoader::parse(&content)?
    };

    let file = path.display().to_string();
    let lib = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown_lib")
        .to_string();

    Ok(lint_chains(&chains, &file, &lib, config))
}

pub fn classify_parse_error(err: &str) -> Option<(String, String)> {
    let normalized = err.replace('\n', " ");
    let has_command_subst = normalized.contains("$(");
    let has_operator = normalized.contains("&&") || normalized.contains("||") || normalized.contains(';');
    if has_command_subst && has_operator {
        return Some((
            "PC-LINT-4103".to_string(),
            "Invalid command substitution syntax: $(...) accepts exactly one command. Move logical composition outside $(...) and use capture/if for branching.".to_string(),
        ));
    }

    None
}

pub fn lint_xml_content(
    content: &str,
    file: &str,
    lib: &str,
    config: &LintConfig,
) -> Result<Vec<Diagnostic>, String> {
    let chains = ProcessChainXMLLoader::parse(content)?;
    Ok(lint_chains(&chains, file, lib, config))
}

pub fn lint_chains(
    chains: &[ProcessChain],
    file: &str,
    lib: &str,
    config: &LintConfig,
) -> Vec<Diagnostic> {
    let mut analyzer = Analyzer::new(file, lib, config.known_vars.clone());
    analyzer.analyze(chains);
    analyzer.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarScope {
    Global,
    Chain,
    Block,
}

#[derive(Debug, Clone)]
struct VarDef {
    name: String,
    used: bool,
    overwritten_before_use: bool,
    location: VarLocation,
}

#[derive(Debug, Clone)]
struct VarLocation {
    chain: String,
    block: String,
    line: usize,
    source: String,
}

#[derive(Debug, Default, Clone)]
struct ScopeTable {
    current: HashMap<String, usize>,
    defs: Vec<VarDef>,
}

impl ScopeTable {
    fn define(&mut self, name: String, location: VarLocation) -> Option<VarLocation> {
        let overwritten = self.current.get(&name).copied().and_then(|idx| {
            let prev = self.defs.get_mut(idx)?;
            if prev.used {
                None
            } else {
                prev.overwritten_before_use = true;
                Some(prev.location.clone())
            }
        });

        let idx = self.defs.len();
        self.defs.push(VarDef {
            name: name.clone(),
            used: false,
            overwritten_before_use: false,
            location,
        });
        self.current.insert(name, idx);
        overwritten
    }

    fn mark_used(&mut self, name: &str) -> bool {
        if let Some(idx) = self.current.get(name).copied() {
            if let Some(def) = self.defs.get_mut(idx) {
                def.used = true;
            }
            true
        } else {
            false
        }
    }
}

struct Analyzer {
    file: String,
    lib: String,
    known_vars: HashSet<String>,
    diagnostics: Vec<Diagnostic>,
    global_scope: ScopeTable,
}

impl Analyzer {
    fn new(file: &str, lib: &str, known_vars: HashSet<String>) -> Self {
        Self {
            file: file.to_string(),
            lib: lib.to_string(),
            known_vars,
            diagnostics: Vec::new(),
            global_scope: ScopeTable::default(),
        }
    }

    fn analyze(&mut self, chains: &[ProcessChain]) {
        for chain in chains {
            self.analyze_chain(chain);
        }

        let global_scope = self.global_scope.clone();
        self.emit_unused_defs(&global_scope, VarScope::Global);
    }

    fn analyze_chain(&mut self, chain: &ProcessChain) {
        let mut chain_scope = ScopeTable::default();
        for block in chain.get_blocks() {
            let mut block_scope = ScopeTable::default();
            self.analyze_block(chain.id(), block, &mut chain_scope, &mut block_scope);
            self.emit_unused_defs(&block_scope, VarScope::Block);
        }
        self.emit_unused_defs(&chain_scope, VarScope::Chain);
    }

    fn analyze_block(
        &mut self,
        chain_id: &str,
        block: &Block,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        for (index, line) in block.lines.iter().enumerate() {
            let line_no = index + 1;
            for statement in &line.statements {
                self.analyze_statement(
                    chain_id,
                    &block.id,
                    line_no,
                    line.source.as_str(),
                    statement,
                    chain_scope,
                    block_scope,
                );
            }
        }
    }

    fn analyze_statement(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        statement: &Statement,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        if let Some(if_stmt) = statement.if_statement.as_ref() {
            self.analyze_if_statement(
                chain_id,
                block_id,
                line,
                source,
                if_stmt,
                chain_scope,
                block_scope,
            );
        } else {
            self.analyze_expression_chain(
                chain_id,
                block_id,
                line,
                source,
                &statement.expressions,
                chain_scope,
                block_scope,
            );
        }
    }

    fn analyze_if_statement(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        if_stmt: &IfStatement,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        for branch in &if_stmt.branches {
            self.analyze_expression_chain(
                chain_id,
                block_id,
                line,
                source,
                &branch.condition,
                chain_scope,
                block_scope,
            );
            for (idx, nested_line) in branch.lines.iter().enumerate() {
                let nested_line_no = line + idx + 1;
                for statement in &nested_line.statements {
                    self.analyze_statement(
                        chain_id,
                        block_id,
                        nested_line_no,
                        nested_line.source.as_str(),
                        statement,
                        chain_scope,
                        block_scope,
                    );
                }
            }
        }

        if let Some(else_lines) = if_stmt.else_lines.as_ref() {
            for (idx, nested_line) in else_lines.iter().enumerate() {
                let nested_line_no = line + idx + 1;
                for statement in &nested_line.statements {
                    self.analyze_statement(
                        chain_id,
                        block_id,
                        nested_line_no,
                        nested_line.source.as_str(),
                        statement,
                        chain_scope,
                        block_scope,
                    );
                }
            }
        }
    }

    fn analyze_expression_chain(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        chain: &ExpressionChain,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        for (_, expr, _) in chain {
            self.analyze_expression(
                chain_id,
                block_id,
                line,
                source,
                expr,
                chain_scope,
                block_scope,
            );
        }
    }

    fn analyze_expression(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        expr: &Expression,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        match expr {
            Expression::Command(cmd) => {
                self.analyze_command(
                    chain_id,
                    block_id,
                    line,
                    source,
                    cmd.command.name.as_str(),
                    cmd.command.args.as_slice(),
                    chain_scope,
                    block_scope,
                );
            }
            Expression::Group(group) => {
                self.analyze_expression_chain(
                    chain_id,
                    block_id,
                    line,
                    source,
                    group,
                    chain_scope,
                    block_scope,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_command(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        command_name: &str,
        args: &[CommandArg],
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        let mut skip_read_indices = HashSet::new();

        if command_name == "assign" {
            self.handle_assign_definition(
                chain_id,
                block_id,
                line,
                source,
                args,
                chain_scope,
                block_scope,
                &mut skip_read_indices,
            );
        } else if command_name == "capture" {
            self.handle_capture_definition(
                chain_id,
                block_id,
                line,
                source,
                args,
                block_scope,
                &mut skip_read_indices,
            );
        }

        self.mark_regex_template_skip_reads(command_name, args, &mut skip_read_indices);
        self.detect_loose_compare(chain_id, block_id, line, source, command_name, args);
        self.detect_regex_template_pitfall(chain_id, block_id, line, source, command_name, args);

        for (idx, arg) in args.iter().enumerate() {
            if skip_read_indices.contains(&idx) {
                continue;
            }
            self.analyze_arg_reads(
                chain_id,
                block_id,
                line,
                source,
                arg,
                chain_scope,
                block_scope,
            );
        }
    }

    fn mark_regex_template_skip_reads(
        &self,
        command_name: &str,
        args: &[CommandArg],
        skip_read_indices: &mut HashSet<usize>,
    ) {
        let Some(index) = Self::rewrite_regex_template_index(command_name, args) else {
            return;
        };

        if matches!(
            args[index],
            CommandArg::Literal(_) | CommandArg::StringLiteral(_) | CommandArg::TypedLiteral(_, _)
        ) {
            // In rewrite-reg/rewrite-regex template context, `$x` means template text (or typo),
            // not a DSL variable read. We do context-aware lint in dedicated checks.
            skip_read_indices.insert(index);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_assign_definition(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        args: &[CommandArg],
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
        skip_read_indices: &mut HashSet<usize>,
    ) {
        let mut base = 0usize;
        if args
            .first()
            .and_then(CommandArg::as_literal_str)
            .is_some_and(|v| v == "assign")
        {
            base = 1;
            skip_read_indices.insert(0);
        }

        if args.len() < base + 2 {
            return;
        }

        skip_read_indices.insert(base);
        skip_read_indices.insert(base + 1);

        if args.len() < base + 3 {
            return;
        }

        let scope = match args[base].as_literal_str().unwrap_or("chain") {
            "global" | "export" => VarScope::Global,
            "block" | "local" => VarScope::Block,
            _ => VarScope::Chain,
        };

        if let Some(var_name) = Self::arg_as_name(&args[base + 1]) {
            let location = VarLocation {
                chain: chain_id.to_string(),
                block: block_id.to_string(),
                line,
                source: source.to_string(),
            };
            self.define_var(scope, var_name, location, chain_scope, block_scope);
        }
    }

    fn handle_capture_definition(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        args: &[CommandArg],
        block_scope: &mut ScopeTable,
        skip_read_indices: &mut HashSet<usize>,
    ) {
        let mut i = 0usize;
        if args
            .first()
            .and_then(CommandArg::as_literal_str)
            .is_some_and(|v| v == "capture")
        {
            skip_read_indices.insert(0);
            i = 1;
        }

        while i < args.len() {
            let opt = args[i].as_literal_str();
            let Some(opt) = opt else {
                i += 1;
                continue;
            };

            let need_define = matches!(
                opt,
                "--value"
                    | "--status"
                    | "--ok"
                    | "--error"
                    | "--control"
                    | "--control-kind"
                    | "--from"
            );
            if need_define && i + 1 < args.len() {
                skip_read_indices.insert(i);
                skip_read_indices.insert(i + 1);
                if let Some(var_name) = Self::arg_as_name(&args[i + 1]) {
                    let location = VarLocation {
                        chain: chain_id.to_string(),
                        block: block_id.to_string(),
                        line,
                        source: source.to_string(),
                    };
                    self.define_var(
                        VarScope::Block,
                        var_name,
                        location,
                        &mut ScopeTable::default(),
                        block_scope,
                    );
                }
                i += 2;
                continue;
            }

            i += 1;
        }
    }

    fn detect_loose_compare(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        command_name: &str,
        args: &[CommandArg],
    ) {
        let compare = matches!(command_name, "eq" | "ne" | "gt" | "ge" | "lt" | "le");
        if !compare {
            return;
        }

        if args
            .iter()
            .any(|arg| arg.as_literal_str().is_some_and(|v| v == "--loose"))
        {
            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-4001".to_string(),
                severity: LintSeverity::Warning,
                message: format!(
                    "Loose comparison detected in '{}' command; consider strict comparison to avoid implicit conversion risks",
                    command_name
                ),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: chain_id.to_string(),
                block: block_id.to_string(),
                line,
                source: source.to_string(),
            });
        }
    }

    fn detect_regex_template_pitfall(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        command_name: &str,
        args: &[CommandArg],
    ) {
        let Some(template_index) = Self::rewrite_regex_template_index(command_name, args) else {
            return;
        };

        let Some(template) = args[template_index].as_literal_str() else {
            return;
        };

        let chars: Vec<char> = template.chars().collect();
        let mut warn_non_capture_dollar = false;
        let mut warn_multi_digit_capture = false;
        for i in 0..chars.len() {
            if chars[i] != '$' {
                continue;
            }

            let escaped = i > 0 && chars[i - 1] == '\\';
            let next = chars.get(i + 1).copied();
            match next {
                Some(next_char) if next_char.is_ascii_digit() => {
                    if escaped {
                        warn_non_capture_dollar = true;
                    }
                    if chars.get(i + 2).is_some_and(|c| c.is_ascii_digit()) {
                        warn_multi_digit_capture = true;
                    }
                }
                Some('$') => {}
                Some(_) | None => {
                    warn_non_capture_dollar = true;
                }
            }
        }

        if warn_non_capture_dollar {
            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-4101".to_string(),
                severity: LintSeverity::Warning,
                message: "In rewrite-reg/rewrite-regex template, '$' is not DSL variable interpolation. Only '$<digit>' is capture replacement.".to_string(),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: chain_id.to_string(),
                block: block_id.to_string(),
                line,
                source: source.to_string(),
            });
        }

        if warn_multi_digit_capture {
            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-4102".to_string(),
                severity: LintSeverity::Warning,
                message: "rewrite-reg/rewrite-regex template uses multi-digit capture like '$10'; runtime currently treats it as '$1' plus literal '0'.".to_string(),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: chain_id.to_string(),
                block: block_id.to_string(),
                line,
                source: source.to_string(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_arg_reads(
        &mut self,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        arg: &CommandArg,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        match arg {
            CommandArg::Var(expr) => {
                for read in extract_reads_from_var_expression(expr) {
                    self.mark_var_used(
                        &read.name,
                        read.optional,
                        chain_id,
                        block_id,
                        line,
                        source,
                        chain_scope,
                        block_scope,
                    );
                }
            }
            CommandArg::StringLiteral(text) => {
                for read in extract_reads_from_dollar(text) {
                    self.mark_var_used(
                        &read.name,
                        read.optional,
                        chain_id,
                        block_id,
                        line,
                        source,
                        chain_scope,
                        block_scope,
                    );
                }
            }
            CommandArg::CommandSubstitution(expr) => {
                self.analyze_expression(
                    chain_id,
                    block_id,
                    line,
                    source,
                    expr,
                    chain_scope,
                    block_scope,
                );
            }
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_var_used(
        &mut self,
        name: &str,
        optional: bool,
        chain_id: &str,
        block_id: &str,
        line: usize,
        source: &str,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        if self.is_known_var(name) {
            return;
        }

        if block_scope.mark_used(name)
            || chain_scope.mark_used(name)
            || self.global_scope.mark_used(name)
        {
            return;
        }

        if optional {
            // Optional reads from safe/coalesce paths are treated as best-effort to avoid false positives.
            return;
        }

        self.diagnostics.push(Diagnostic {
            code: "PC-LINT-1001".to_string(),
            severity: LintSeverity::Error,
            message: format!("Undefined variable '{}'", name),
            file: self.file.clone(),
            lib: self.lib.clone(),
            chain: chain_id.to_string(),
            block: block_id.to_string(),
            line,
            source: source.to_string(),
        });
    }

    fn define_var(
        &mut self,
        scope: VarScope,
        name: String,
        location: VarLocation,
        chain_scope: &mut ScopeTable,
        block_scope: &mut ScopeTable,
    ) {
        if self.is_known_var(&name) {
            return;
        }

        let mut shadow_scope = None;
        match scope {
            VarScope::Chain => {
                if self.global_scope.current.contains_key(&name) {
                    shadow_scope = Some("global");
                }
            }
            VarScope::Block => {
                if chain_scope.current.contains_key(&name) {
                    shadow_scope = Some("chain");
                } else if self.global_scope.current.contains_key(&name) {
                    shadow_scope = Some("global");
                }
            }
            VarScope::Global => {}
        }

        if let Some(outer_scope) = shadow_scope {
            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-3002".to_string(),
                severity: LintSeverity::Warning,
                message: format!(
                    "Variable '{}' shadows an existing {} scope variable",
                    name, outer_scope
                ),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: location.chain.clone(),
                block: location.block.clone(),
                line: location.line,
                source: location.source.clone(),
            });
        }

        let overwritten = match scope {
            VarScope::Global => self.global_scope.define(name.clone(), location.clone()),
            VarScope::Chain => chain_scope.define(name.clone(), location.clone()),
            VarScope::Block => block_scope.define(name.clone(), location.clone()),
        };

        if let Some(prev_location) = overwritten {
            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-3003".to_string(),
                severity: LintSeverity::Warning,
                message: format!(
                    "Variable '{}' is overwritten before being read (previous definition at line {})",
                    name, prev_location.line
                ),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: location.chain.clone(),
                block: location.block.clone(),
                line: location.line,
                source: location.source.clone(),
            });
        }
    }

    fn emit_unused_defs(&mut self, table: &ScopeTable, scope: VarScope) {
        for def in &table.defs {
            if def.used
                || def.overwritten_before_use
                || self.is_known_var(&def.name)
                || def.name.starts_with('_')
            {
                continue;
            }

            let scope_name = match scope {
                VarScope::Global => "global",
                VarScope::Chain => "chain",
                VarScope::Block => "block",
            };

            self.diagnostics.push(Diagnostic {
                code: "PC-LINT-3001".to_string(),
                severity: LintSeverity::Warning,
                message: format!(
                    "Variable '{}' is defined but not used in {} scope",
                    def.name, scope_name
                ),
                file: self.file.clone(),
                lib: self.lib.clone(),
                chain: def.location.chain.clone(),
                block: def.location.block.clone(),
                line: def.location.line,
                source: def.location.source.clone(),
            });
        }
    }

    fn finish(mut self) -> Vec<Diagnostic> {
        self.diagnostics.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then_with(|| b.severity.rank().cmp(&a.severity.rank()))
                .then_with(|| a.chain.cmp(&b.chain))
                .then_with(|| a.block.cmp(&b.block))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.code.cmp(&b.code))
        });
        self.diagnostics
    }

    fn is_known_var(&self, name: &str) -> bool {
        self.known_vars.contains(name) || name.starts_with("__")
    }

    fn arg_as_name(arg: &CommandArg) -> Option<String> {
        let raw = arg.as_str();
        extract_primary_root(raw)
    }

    fn rewrite_regex_template_index(command_name: &str, args: &[CommandArg]) -> Option<usize> {
        if !matches!(command_name, "rewrite-reg" | "rewrite-regex") {
            return None;
        }

        let mut base = 0usize;
        if args
            .first()
            .and_then(CommandArg::as_literal_str)
            .is_some_and(|v| matches!(v, "rewrite-reg" | "rewrite-regex"))
        {
            base = 1;
        }

        let index = base + 2;
        if args.len() > index {
            Some(index)
        } else {
            None
        }
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn extract_primary_root(text: &str) -> Option<String> {
    let mut s = text.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(rest) = s.strip_prefix('$') {
        s = rest.trim_start();
    }

    if s.starts_with('{') && s.ends_with('}') && s.len() >= 2 {
        s = &s[1..s.len() - 1];
    }

    let mut chars = s.chars();
    let first = chars.next()?;
    if !is_ident_start(first) {
        return None;
    }

    let mut root = String::new();
    root.push(first);
    for c in chars {
        if !is_ident_continue(c) {
            break;
        }
        root.push(c);
    }

    Some(root)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VarRead {
    name: String,
    optional: bool,
}

fn contains_optional_access_or_coalesce(expr: &str) -> bool {
    expr.contains("?.") || expr.contains("?[") || expr.contains("??")
}

fn extract_reads_from_var_expression(expr: &str) -> Vec<VarRead> {
    let mut reads = Vec::new();
    let root_optional = contains_optional_access_or_coalesce(expr);
    if let Some(root) = extract_primary_root(expr) {
        reads.push(VarRead {
            name: root,
            optional: root_optional,
        });
    }
    reads.extend(extract_reads_from_dollar(expr));

    dedup_reads(reads)
}

fn extract_reads_from_dollar(text: &str) -> Vec<VarRead> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut result = Vec::<VarRead>::new();

    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        if i > 0 && bytes[i - 1] == b'\\' {
            i += 1;
            continue;
        }

        if i + 1 >= bytes.len() {
            break;
        }

        if bytes[i + 1] == b'{' {
            let mut j = i + 2;
            let mut depth = 1usize;
            while j < bytes.len() {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }

            if j < bytes.len() && depth == 0 {
                let inner = &text[i + 2..j];
                if let Some(root) = extract_primary_root(inner) {
                    result.push(VarRead {
                        name: root,
                        optional: contains_optional_access_or_coalesce(inner),
                    });
                }
                result.extend(extract_reads_from_dollar(inner));
                i = j + 1;
                continue;
            }

            i += 1;
            continue;
        }

        let mut chars = text[i + 1..].char_indices();
        let Some((_, first)) = chars.next() else {
            break;
        };
        if !is_ident_start(first) {
            i += 1;
            continue;
        }

        let mut end = i + 1 + first.len_utf8();
        for (offset, c) in chars {
            if !is_ident_continue(c) {
                end = i + 1 + offset;
                break;
            }
            end = i + 1 + offset + c.len_utf8();
        }

        result.push(VarRead {
            name: text[i + 1..end].to_string(),
            optional: false,
        });
        i = end;
    }

    dedup_reads(result)
}

fn dedup_reads(values: Vec<VarRead>) -> Vec<VarRead> {
    let mut merged = BTreeMap::<String, bool>::new();
    for value in values {
        if value.name.is_empty() {
            continue;
        }
        match merged.get_mut(&value.name) {
            Some(existing_optional) => {
                if *existing_optional && !value.optional {
                    *existing_optional = false;
                }
            }
            None => {
                merged.insert(value.name, value.optional);
            }
        }
    }

    merged
        .into_iter()
        .map(|(name, optional)| VarRead { name, optional })
        .collect()
}

#[cfg(test)]
mod test;
