use crate::block::CommandArgs;

pub struct CommandArgHelper;

impl CommandArgHelper {
    pub fn parse_options<'a>(
        args: &'a [&'a str],
        options: &[&[&str]],
    ) -> Result<Vec<&'a str>, String> {
        let mut ret: Vec<&str> = vec![];
        let mut group_index = vec![];

        for arg in args {
            let arg = arg.trim();
            if !arg.starts_with('-') && !arg.starts_with("--") {
                break;
            }

            let opt = arg.trim_start_matches('-');
            let mut found = false;

            // Check by group
            for (index, group) in options.iter().enumerate() {
                if group.contains(&opt) {
                    if group_index.contains(&index) {
                        let msg = format!("Option '{}' already exists in group {}", arg, index);
                        error!("{}", msg);
                        return Err(msg);
                    }

                    // Add to group index
                    group_index.push(index);
                    ret.push(opt);
                    found = true;

                    break;
                }
            }

            if !found {
                // If not found in any group, return error
                let msg = format!("Invalid option '{}', expected one of {:?}", arg, options);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(ret)
    }

    pub fn check_origin_options(args: &CommandArgs, options: &[&[&str]]) -> Result<usize, String> {
        let mut group_index = vec![];
        let mut option_count = 0;

        for arg in args.iter() {
            if !arg.is_literal() {
                break;
            }

            let arg = arg.as_literal_str().unwrap();
            if !arg.starts_with('-') && !arg.starts_with("--") {
                break;
            }

            let opt = arg.trim_start_matches('-');
            option_count += 1;

            // Check by group
            let mut found = false;
            for (index, group) in options.iter().enumerate() {
                if group.contains(&opt) {
                    if group_index.contains(&index) {
                        let msg = format!("Option '{}' already exists in group {}", arg, index);
                        error!("{}", msg);
                        return Err(msg);
                    }

                    // Add to group index
                    group_index.push(index);
                    found = true;

                    break;
                }
            }

            if !found {
                // If not found in any group, return error
                let msg = format!("Invalid option '{}', expected one of {:?}", arg, options);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(option_count)
    }
}
