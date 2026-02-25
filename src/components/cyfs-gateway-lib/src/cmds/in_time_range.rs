use chrono::{Datelike, Local, NaiveDate, Timelike, Utc};
use clap::{Arg, ArgAction, Command};
use cyfs_process_chain::{
    CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, ExternalCommand,
    command_help,
};

pub struct InTimeRange {
    name: String,
    cmd: Command,
}

impl InTimeRange {
    pub fn new() -> Self {
        let cmd = Command::new("in-time-range")
            .about("Check whether current time is within specified conditions")
            .after_help(
                r#"
Examples:
    in-time-range --hour 9-18 --minute */5
    in-time-range --weekday mon-fri --hour 9-18
    in-time-range --monthday 1,15,30
    in-time-range --month 1-3 --date 2026-02-01..2026-02-28

Spec syntax:
    *           any value
    n           exact value
    a-b         inclusive range
    a,b,c       list
    */k         step (from minimum of field)

Field ranges:
    minute      0-59
    hour        0-23
    weekday     1-7 or mon..sun (1=Mon, 7=Sun)
    monthday    1-31
    month       1-12
    date        YYYY-MM-DD or YYYY-MM-DD..YYYY-MM-DD (supports list)
                "#,
            )
            .arg(
                Arg::new("minute")
                    .long("minute")
                    .help("Minute spec: 0-59")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("hour")
                    .long("hour")
                    .help("Hour spec: 0-23")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("weekday")
                    .long("weekday")
                    .help("Weekday spec: 1-7 or mon..sun")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("monthday")
                    .long("monthday")
                    .help("Day of month spec: 1-31")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("month")
                    .long("month")
                    .help("Month spec: 1-12")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("date")
                    .long("date")
                    .help("Date spec: YYYY-MM-DD or YYYY-MM-DD..YYYY-MM-DD")
                    .num_args(1)
                    .required(false),
            )
            .arg(
                Arg::new("utc")
                    .long("utc")
                    .help("Use UTC instead of local time")
                    .action(ArgAction::SetTrue),
            );

        Self {
            name: "in-time-range".to_string(),
            cmd,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn has_any_condition(matches: &clap::ArgMatches) -> bool {
        matches.contains_id("minute")
            || matches.contains_id("hour")
            || matches.contains_id("weekday")
            || matches.contains_id("monthday")
            || matches.contains_id("month")
            || matches.contains_id("date")
    }

    fn parse_u32_in_range(input: &str, min: u32, max: u32, field: &str) -> Result<u32, String> {
        let value = input.parse::<u32>().map_err(|e| {
            format!(
                "invalid {} value '{}': {}, expected range {}-{}",
                field, input, e, min, max
            )
        })?;

        if value < min || value > max {
            return Err(format!(
                "invalid {} value '{}': out of range {}-{}",
                field, input, min, max
            ));
        }

        Ok(value)
    }

    fn match_numeric_spec(
        value: u32,
        spec: &str,
        min: u32,
        max: u32,
        field: &str,
    ) -> Result<bool, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(format!("{} spec is empty", field));
        }

        if spec == "*" {
            return Ok(true);
        }

        for raw_token in spec.split(',') {
            let token = raw_token.trim();
            if token.is_empty() {
                return Err(format!("{} spec contains empty token: '{}'", field, spec));
            }

            if token == "*" {
                return Ok(true);
            }

            if let Some(step_str) = token.strip_prefix("*/") {
                let step = step_str
                    .parse::<u32>()
                    .map_err(|e| format!("invalid {} step '{}': {}", field, step_str, e))?;
                if step == 0 {
                    return Err(format!("invalid {} step: must be > 0", field));
                }
                if value >= min && value <= max && (value - min).is_multiple_of(step) {
                    return Ok(true);
                }
                continue;
            }

            if let Some((start_str, end_str)) = token.split_once('-') {
                let start = Self::parse_u32_in_range(start_str.trim(), min, max, field)?;
                let end = Self::parse_u32_in_range(end_str.trim(), min, max, field)?;
                if start > end {
                    return Err(format!(
                        "invalid {} range '{}': begin must be <= end",
                        field, token
                    ));
                }
                if value >= start && value <= end {
                    return Ok(true);
                }
                continue;
            }

            let item = Self::parse_u32_in_range(token, min, max, field)?;
            if value == item {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn parse_weekday_value(input: &str) -> Result<u32, String> {
        let v = input.trim().to_ascii_lowercase();
        match v.as_str() {
            "1" | "mon" | "monday" => Ok(1),
            "2" | "tue" | "tues" | "tuesday" => Ok(2),
            "3" | "wed" | "wednesday" => Ok(3),
            "4" | "thu" | "thur" | "thurs" | "thursday" => Ok(4),
            "5" | "fri" | "friday" => Ok(5),
            "6" | "sat" | "saturday" => Ok(6),
            "7" | "sun" | "sunday" => Ok(7),
            _ => Err(format!(
                "invalid weekday '{}', expected 1-7 or mon..sun",
                input
            )),
        }
    }

    fn match_weekday_spec(value: u32, spec: &str) -> Result<bool, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("weekday spec is empty".to_string());
        }
        if spec == "*" {
            return Ok(true);
        }

        for raw_token in spec.split(',') {
            let token = raw_token.trim();
            if token.is_empty() {
                return Err(format!("weekday spec contains empty token: '{}'", spec));
            }

            if token == "*" {
                return Ok(true);
            }

            if let Some(step_str) = token.strip_prefix("*/") {
                let step = step_str
                    .parse::<u32>()
                    .map_err(|e| format!("invalid weekday step '{}': {}", step_str, e))?;
                if step == 0 {
                    return Err("invalid weekday step: must be > 0".to_string());
                }
                if (value - 1).is_multiple_of(step) {
                    return Ok(true);
                }
                continue;
            }

            if let Some((start_str, end_str)) = token.split_once('-') {
                let start = Self::parse_weekday_value(start_str)?;
                let end = Self::parse_weekday_value(end_str)?;
                if start > end {
                    return Err(format!(
                        "invalid weekday range '{}': begin must be <= end",
                        token
                    ));
                }
                if value >= start && value <= end {
                    return Ok(true);
                }
                continue;
            }

            if value == Self::parse_weekday_value(token)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn parse_date(input: &str) -> Result<NaiveDate, String> {
        NaiveDate::parse_from_str(input.trim(), "%Y-%m-%d")
            .map_err(|e| format!("invalid date '{}': {}", input, e))
    }

    fn match_date_spec(value: NaiveDate, spec: &str) -> Result<bool, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err("date spec is empty".to_string());
        }

        for raw_token in spec.split(',') {
            let token = raw_token.trim();
            if token.is_empty() {
                return Err(format!("date spec contains empty token: '{}'", spec));
            }

            if let Some((start_str, end_str)) = token.split_once("..") {
                let start = Self::parse_date(start_str)?;
                let end = Self::parse_date(end_str)?;
                if start > end {
                    return Err(format!(
                        "invalid date range '{}': begin must be <= end",
                        token
                    ));
                }
                if value >= start && value <= end {
                    return Ok(true);
                }
                continue;
            }

            let date = Self::parse_date(token)?;
            if value == date {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn validate_specs(matches: &clap::ArgMatches) -> Result<(), String> {
        if let Some(spec) = matches.get_one::<String>("minute") {
            let _ = Self::match_numeric_spec(0, spec, 0, 59, "minute")?;
        }
        if let Some(spec) = matches.get_one::<String>("hour") {
            let _ = Self::match_numeric_spec(0, spec, 0, 23, "hour")?;
        }
        if let Some(spec) = matches.get_one::<String>("weekday") {
            let _ = Self::match_weekday_spec(1, spec)?;
        }
        if let Some(spec) = matches.get_one::<String>("monthday") {
            let _ = Self::match_numeric_spec(1, spec, 1, 31, "monthday")?;
        }
        if let Some(spec) = matches.get_one::<String>("month") {
            let _ = Self::match_numeric_spec(1, spec, 1, 12, "month")?;
        }
        if let Some(spec) = matches.get_one::<String>("date") {
            let _ = Self::match_date_spec(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap(), spec)?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ExternalCommand for InTimeRange {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid in-time-range command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        if !Self::has_any_condition(&matches) {
            return Err(
                "at least one condition is required (minute/hour/weekday/monthday/month/date)"
                    .to_string(),
            );
        }

        Self::validate_specs(&matches)
    }

    async fn exec(
        &self,
        _context: &Context,
        args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self.cmd.clone().try_get_matches_from(&str_args).map_err(|e| {
            let msg = format!("Invalid in-time-range command: {:?}, {}", args, e);
            error!("{}", msg);
            msg
        })?;

        if !Self::has_any_condition(&matches) {
            return Err(
                "at least one condition is required (minute/hour/weekday/monthday/month/date)"
                    .to_string(),
            );
        }

        Self::validate_specs(&matches)?;

        let use_utc = matches.get_flag("utc");

        let (minute, hour, weekday, monthday, month, date) = if use_utc {
            let now = Utc::now();
            (
                now.minute(),
                now.hour(),
                now.weekday().num_days_from_monday() + 1,
                now.day(),
                now.month(),
                now.date_naive(),
            )
        } else {
            let now = Local::now();
            (
                now.minute(),
                now.hour(),
                now.weekday().num_days_from_monday() + 1,
                now.day(),
                now.month(),
                now.date_naive(),
            )
        };

        if let Some(spec) = matches.get_one::<String>("minute") {
            if !Self::match_numeric_spec(minute, spec, 0, 59, "minute")? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        if let Some(spec) = matches.get_one::<String>("hour") {
            if !Self::match_numeric_spec(hour, spec, 0, 23, "hour")? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        if let Some(spec) = matches.get_one::<String>("weekday") {
            if !Self::match_weekday_spec(weekday, spec)? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        if let Some(spec) = matches.get_one::<String>("monthday") {
            if !Self::match_numeric_spec(monthday, spec, 1, 31, "monthday")? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        if let Some(spec) = matches.get_one::<String>("month") {
            if !Self::match_numeric_spec(month, spec, 1, 12, "month")? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        if let Some(spec) = matches.get_one::<String>("date") {
            if !Self::match_date_spec(date, spec)? {
                return Ok(CommandResult::error_with_value("false"));
            }
        }

        Ok(CommandResult::success_with_value("true"))
    }
}
