# Command reference documentation

## string

### `append`
```
Append two or more string parameters and return the result.

Usage: append <params> <params>...

Arguments:
  <params> <params>...
          Two or more values to append

Options:
  -h, --help
          Print help


Arguments:
  <params>...  Two or more strings or variables to append

Behavior:
  - Joins all parameters with no delimiter.
  - Output is returned with success.
  - The command will not modify any env variables unless specified.

Examples:
  append "abc" "123"
  append $REQ.host ".internal" ".com"
  append "prefix-" $VAR "-suffix"
```

### `ends-with`
```
Check if a string ends with the given suffix.

Usage: ends-with [OPTIONS] <string> <suffix>

Arguments:
  <string>
          Input string to check

  <suffix>
          Suffix to test against

Options:
  -i, --ignore-case
          Perform case-insensitive comparison

  -h, --help
          Print help


Arguments:
  <string>   The full input string.
  <suffix>   The suffix to check.

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:

    - Returns true if <string> ends with <suffix>.
    - Comparison is case-sensitive by default.
    - Does not modify any variable or environment.

Examples:
  ends-with "hello world" "world"       → true
  ends-with $REQ.url ".html"            → false
  ends-with "example.com" ".com"        → true
```

### `replace`
```
Replace all occurrences of a substring in a variable’s value.

Usage: replace [OPTIONS] <var> <match> <replacement>

Arguments:
  <var>
          Variable name to modify

  <match>
          Text to search for

  <replacement>
          Text to replace with

Options:
  -i, --ignore-case
          Perform case-insensitive comparison

  -h, --help
          Print help


Arguments:
  <var>         The name of the variable to modify (e.g. $REQ.host)
  <match>       The substring to search for
  <replacement> The string to replace it with

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:
  - Replaces all (non-overlapping) occurrences of <match> with <replacement>.
  - Case-sensitive by default.
  - If <match> is not found, the variable remains unchanged.

Examples:
  replace $REQ.host "io" "ai"
  replace $PATH "/old/" "/new/"
```

### `rewrite`
```
Rewrite the value of a variable using a glob pattern.

Usage: rewrite <var> <pattern> <template>

Arguments:
  <var>
          The name of the variable to rewrite

  <pattern>
          The glob pattern to match

  <template>
          The replacement template

Options:
  -h, --help
          Print help


Arguments:
  <var>       The variable to rewrite (e.g. $REQ.url)
  <pattern>   A glob-style pattern to match (e.g. /kapi/my-service/*)
  <template>  A replacement template using * wildcard (e.g. /kapi/*)

Behavior:
  - Performs case-insensitive glob pattern match.
  - Supports only a single '*' wildcard in pattern/template.
  - Rewrites the variable if pattern matches, replacing the '*' part.

Examples:
  rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
  rewrite host "api.*.domain.com" "svc-*.internal"
```

### `rewrite-reg`
```
Rewrite a variable using a regular expression and a replacement template.

Usage: rewrite-regex <var> <regex> <template>

Arguments:
  <var>
          The variable to rewrite

  <regex>
          The regular expression pattern

  <template>
          The replacement template

Options:
  -h, --help
          Print help


Arguments:
  <var>        The name of the variable to rewrite (e.g. $REQ.url)
  <regex>      Regular expression pattern to match (with capture groups)
  <template>   Replacement string using $1, $2, ... for captured groups

Behavior:
  - If the regex matches, rewrites the variable with the template.
  - Unmatched captures are replaced with empty strings.
  - If the pattern does not match, the variable remains unchanged.

Examples:
  rewrite-regex $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
```

### `slice`
```
Slice a string by byte range and return the result.

Usage: slice <string> <range>

Arguments:
  <string>
          String to slice

  <range>
          Slice range in format start:end

Options:
  -h, --help
          Print help


Arguments:
  <string>       The input string or variable to slice.
  <start:end>    Byte index range. End is exclusive.

Behavior:
  - Uses UTF-8-safe slicing based on byte indices.
  - Returns a substring starting at `start` and ending before `end`.
  - If end is less than or equal to start, returns an empty string.
  - Does not modify any variable or environment.

Examples:
  slice "abcdef" 1:4
  slice $REQ.url 0:10
```

### `starts-with`
```
Check if a string starts with the given prefix.

Usage: starts-with [OPTIONS] <string> <prefix>

Arguments:
  <string>
          Input string to check

  <prefix>
          Prefix to test against

Options:
  -i, --ignore-case
          Perform case-insensitive comparison

  -h, --help
          Print help


Arguments:
  <string>     The full input string.
  <prefix>     The prefix to check.

Options:
  --ignore-case,-i   Perform case-insensitive comparison

Behavior:
  - Returns true if <string> begins with <prefix>.
  - Comparison is case-sensitive by default.
  - Does not modify any variable or environment.

Examples:
  starts-with "hello world" "hello"     → true
  starts-with $REQ.url "/api/"          → true
  starts-with "example.com" "test"      → false
```

### `strlen`
```
Return the character length of a string.

Usage: strlen <string>

Arguments:
  <string>
          Input string to measure

Options:
  -h, --help
          Print help


Arguments:
  <string>     The input string to measure.

Behavior:
  - Returns the number of bytes.
  - Does not modify environment or variables.

Examples:
  strlen "abc"
  strlen "你好"
  strlen $REQ.path
```

## debug

### `echo`
```
Display a line of text or output the given arguments.

Usage: echo [OPTIONS] [args]...

Arguments:
  [args]...
          Text arguments to display

Options:
  -n
          Do not print the trailing newline

  -v, --verbose
          Print additional information about the command execution, such as collections' contents

  -h, --help
          Print help


Options:
  -n          Do not print the trailing newline.
  --verbose   Print additional information about the command execution, such as collections's contents.

Behavior:
  - Joins all arguments with spaces and prints them.
  - By default, a newline is printed at the end.

Examples:
  echo "Hello, World!";
  echo -n "Hello," "World!";
  echo --verbose $REQ;
```

## variable

### `assign`
```
Manage variable definitions and scope preferences.

Usage: 
    [SCOPE] VAR=VALUE     Define or update a variable in the specified scope.
    VAR=VALUE             Define a variable in the default (chain) scope.
    SCOPE VAR             Set the default scope for future references to VAR.

Options:
  -h, --help
          Print help


Scope:
    export, global        Global scope (shared across chains)
    chain                 Chain-level scope (default)
    block, local          Block-level scope

Notes:
    - If a variable already exists, its value will be overwritten.
    - When assigning (VAR=VALUE), scope defaults to 'chain' unless explicitly specified.
    - When only VAR is given after a scope, it sets default lookup scope for VAR.
    - RHS supports non-string values (e.g. Map/Set/MultiMap), not only string.
    - Collection assignment uses reference semantics (shared reference), not deep copy.
      After `a=$b`, mutations through `a` and `b` are visible to each other.

Examples:
    my_var=123
    global my_var=456
    block my_var
    local currentGeo=$geoByIp[$REQ.clientIp]
    local trustedSet=$trustedCountrySet
```

### `capture`
```
Execute a sub-command once, capture its result value/status into local variables, and return the original result.

Usage: capture [OPTIONS] <command>

Arguments:
  <command>
          Sub-command in command substitution form: $(...)

Options:
      --value <VAR>
          Variable name to store CommandResult.value()

      --status <VAR>
          Variable name to store status: success|error|control

  -h, --help
          Print help


Examples:
  capture --value geo --status st $(lookup-geo $clientIp)
  capture --value out $(call check_something $arg)

Notes:
  - The sub-command must be provided as command substitution: $(...)
  - Captured variables are written to block(local) scope.
  - This command returns the original sub-command CommandResult unchanged.
```

### `delete`
```
Delete a variable or collection value from a specified scope.

Usage: delete [--global|--chain|--block] <variable_name>

Arguments:
  <variable_name>
          The name of the variable to delete

Options:
      --global
          Use global scope

      --chain
          Use chain scope (default)

      --block
          Use block (local) scope

  -h, --help
          Print help


Deletes a variable or collection value from the specified scope.

Scope Options:
  --export, --global   Global scope
  --chain              Chain scope
  --block, --local     Block scope

Variable Names:
  - Variable names can include dot-separated paths to access nested values,
    especially for structured collections like set/map/multimap.
  - For example: $REQ.header, $REQ.headers.Host, $USER.config.theme
  - If scope is not specified, defaults to the variable's current scope.

Delete Modes:
  - If the full name refers to a top-level variable (e.g., $REQ, $temp), the entire
    variable will be deleted from the given scope.
  - If the name includes a path (e.g., REQ.header1), the command attempts
    to remove the key `header1` from the container `REQ`.

Examples:
  delete my_var;
  delete --global user_token;
  delete --block tmp_value;
  delete $REQ.header1;
```

### `type`
```
Determine and display the type of the provided argument(s).

Usage: type [OPTIONS] <variable_name>

Arguments:
  <variable_name>
          The name of the variable to get type

Options:
      --global
          Use global scope

      --chain
          Use chain scope (default)

      --block
          Use block (local) scope

  -h, --help
          Print help


Get the type of the given variable or collection value.

Scope Options:
  --export, --global   Global scope
  --chain              Chain scope
  --block, --local     Block scope

Behavior:
  - Evaluates argument and identifies its type.
  - If the target var exists, returns its success(type string).
  - If the target var does not exist, returns error("None").
  - If scope is not specified, defaults to the variable's current scope, default is chain level

Examples:
    type my_var
    type --global $my_var
    type --block my_map.key
```

## external

### `call`
```
Call an external or user-defined command with arguments

Usage: call <command> [args]...

Arguments:
  <command>
          The external command to execute

  [args]...
          Arguments for the external command

Options:
  -h, --help
          Print help


Note:
  - All external commands must be registered with the runtime beforehand.
  - If the command is not found, an error will be returned.
  - This command is useful to invoke plugin-based or user-defined logic
    without polluting the internal command namespace.

Examples:
  call verify_token $REQ.token
  call user_lookup alice
  call plugin.process_json '{"key": "value"}'
```

## collection

### `map-add`
```
Add or update key-value pairs in a map or multimap collection.

Usage: map-add <map_id> <key> <values>...

Arguments:
  <map_id>
          The ID of the target map collection

  <key>
          The key to insert or update

  <values>...
          One or more values to associate with the key

Options:
  -h, --help
          Print help


Arguments:
  <map_id>    The identifier of the map or multimap.
  <key>       The key to insert or update.
  <value>...  One or more values to associate with the key.

Notes:
  - For normal maps, only one value is allowed.
  - For multimaps, multiple values are accepted.
  - Use `map-create` to define the collection before adding items.

Examples:
  map-add session_map session123 user1
  map-add multi_ip_map 192.168.0.1 login blocked
```

### `map-create`
```
Create a new map or multimap collection with a given ID and scope.

Usage: map-create [OPTIONS] <map_id>

Arguments:
  <map_id>
          The ID of the map/multimap to create

Options:
  -m, --multi
          Create a multimap

      --global
          Use global scope
          
          [aliases: --export]

      --chain
          Use chain scope (default)

      --block
          Use block scope
          
          [aliases: --local]

  -h, --help
          Print help


Options:
  -multi                Create a multimap (key → multiple values allowed).
  -global, -export      Global scope (same as -global).
  -chain                Process chain scope (default).
  -block, -local        Block-local scope (same as -block).

Notes:
  - If no scope is specified, the default is chain-level.
  - Use -multi to create a multimap instead of a regular map.

Examples:
  map-create trusted_hosts
  map-create -global user_token_map
  map-create -multi -local ip_event_map
```

### `map-remove`
```
Remove a key or key-value pair(s) from a map or multimap collection.

Usage: map-remove <map_id> <key> [values]...

Arguments:
  <map_id>
          The ID of the map or multimap

  <key>
          The key to remove or update

  [values]...
          Optional value(s) to remove under the key

Options:
  -h, --help
          Print help


Usage:
  map-remove <map_id> <key>
  map-remove <map_id> <key> <value>...
  
Arguments:
  <map_id>    ID of the map or multimap.
  <key>       The key to remove or modify.
  <value>...  Optional. One or more values to remove.

Behavior:
  - If only key is provided, remove the whole entry.
  - If values are given:
      - In map: only one value is allowed.
      - In multimap: all values under the key will be removed.

Examples:
  map-remove session_map session123
  map-remove multi_map 127.0.0.1 login_failed blocked
```

### `match-include`
```
Match keys or key-value pairs within a collection.

Usage: match-include <collection> <key> [value]...

Arguments:
  <collection>
          Target collection variable name or collection id

  <key>
          Key to match in the collection

  [value]...
          One or more values to match with the key

Options:
  -h, --help
          Print help


Match inclusion of a key or key-value(s) in a target collection.
This command supports set, map, and multi-map collection types.

Behavior:
    - match-include <collection> <key>
        Succeeds if <key> exists in a set or map or multi-map collection.

    - match-include <collection> <key> <value>
        Succeeds if the map or multi-map contains the exact (key, value) pair.

    - match-include <collection> <key> <value1> <value2> ...
        For multi-map: succeeds only if ALL (key, valueN) pairs exist in the collection.

Notes:
    - If the target collection does not exist, the match fails.
    - Only exact matches are supported. Glob or regex patterns are NOT supported.
    - Values must be listed as separate arguments (not as a single list).

Examples:
    match-include $test.coll "test_value"
    match-include $HOST $REQ_host "www.test.com" && drop
    match-include $IP $REQ_ip "127.0.0.1" "192.168.100.1" && accept
```

### `set-add`
```
Add one value or more values to a set collection.

Usage: set-add <set_id> <value>...

Arguments:
  <set_id>
          The ID of the target set

  <value>...
          One or more values to add to the set

Options:
  -h, --help
          Print help


Arguments:
  <set_id>    The identifier of the target set.
  <value>...  One or more values to insert into the set.

Notes:
  - If the set does not exist, the operation fails.
  - Sets only store unique values.
  - Use `set-create` to initialize a set before using this command.

Examples:
  set-add trusted_hosts "192.168.1.1" "192.168.100.1"
  set-add temp_set "flag_enabled"
```

### `set-create`
```
Create a new set collection with a given identifier and scope.

Usage: set-create [OPTIONS] <set_id>

Arguments:
  <set_id>
          The ID of the set to create

Options:
      --global
          Use global scope
          
          [aliases: --export]

      --chain
          Use chain scope (default)

      --block
          Use block scope
          
          [aliases: --local]

  -h, --help
          Print help


Arguments:
  <set_id>    The identifier of the set collection to create.

Scope Options:
  -global, -export    Create the set in the global scope.
  -chain              Create the set in the current process chain scope (default).
  -block, -local      Create the set in the current execution block (local) scope.

Notes:
  - If no scope is specified, the default is chain-level.
  - A set is a collection of unique string items.
  - Sets can later be queried using match-include or modified using set-add/set-remove.

Examples:
  set-create -global trusted_hosts
  set-create -export trusted_hosts
  set-create session_flags
  set-create -block temp_set
  set-create -local temp_set
```

### `set-remove`
```
Remove a value from a set collection.

Usage: set-remove <set_id> <value>...

Arguments:
  <set_id>
          The ID of the set to remove from

  <value>...
          One or more values to remove from the set

Options:
  -h, --help
          Print help


Arguments:
  <set_id>    The identifier of the target set.
  <value>...  One or more values to remove from the set.

Notes:
  - If the set does not exist, the operation fails.
  - If the value is not in the set, it is ignored.
  - Sets only store unique values.

Examples:
  set-remove trusted_hosts "192.168.1.1"
  set-remove temp_set "flag_enabled"
```

## match

### `eq`
```
Compare two strings for equality.

Usage: eq [OPTIONS] <value1> <value2>

Arguments:
  <value1>
          The first value to compare

  <value2>
          The second value to compare

Options:
  -i, --ignore-case
          Enable case-insensitive comparison

  -h, --help
          Print help


Compare two strings for equality.

Arguments:
  <value1>        First value to compare
  <value2>        Second value to compare

Options:
  --ignore-case   Perform case-insensitive comparison

By default, the comparison is case-sensitive. Use --ignore-case to enable case-insensitive comparison.

Examples:
  eq "host" "host"
  eq --ignore-case "Host" "HOST"
```

### `match`
```
Match a value using glob pattern.

Usage: match [OPTIONS] <value> <pattern>

Arguments:
  <value>
          The input string or variable to match

  <pattern>
          The glob pattern to match against

Options:
      --no-ignore-case
          Perform case-sensitive matching (default is case-insensitive)

  -h, --help
          Print help


Arguments:
  <value>     The string or variable to match.
  <pattern>   A glob pattern (e.g. *.domain.com, home.*.site.org)

Options:
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses shell-style glob pattern matching.
  - Case-insensitive by default.
  - Pattern must follow shell glob syntax:
      *  — matches any number of characters
      ?  — matches a single character
      [...] — character class

Examples:
  match $REQ_HEADER.host "*.local"
  match username "admin*"
```

### `match-reg`
```
Match a value against a regular expression. Supports optional named capture.

Usage: match-reg [OPTIONS] <value> <pattern>

Arguments:
  <value>
          The input string or variable to match

  <pattern>
          The regular expression pattern

Options:
      --no-ignore-case
          Perform case-sensitive matching (default is case-insensitive)

      --capture <name>
          Name to use when storing regex captures into the environment

  -h, --help
          Print help


Arguments:
  <value>      The string to match.
  <pattern>    The regular expression to match against.

Options:
  --capture name   Capture groups into environment variables like name[0], name[1], ...
  --no-ignore-case   Perform case-sensitive matching (default is case-insensitive)

Behavior:
  - Uses Rust-style regular expressions.
  - If the pattern matches, the command returns success, otherwise it returns error.
  - If --capture is provided, matched groups are saved into environment as:
      name[0] is the first capture group,
      name[1] is the second capture group, etc.
  - Default behavior is case-insensitive matching.

Examples:
  match-reg $REQ_HEADER.host "^(.*)\.local$"
  match-reg --capture parts $REQ_HEADER.host "^(.+)\.(local|dev)$"
```

### `range`
```
Check if a variable's value is within a numeric range.

Usage: range <value> <begin> <end>

Arguments:
  <value>
          The variable or value to test

  <begin>
          Range start (inclusive)

  <end>
          Range end (inclusive)

Options:
  -h, --help
          Print help


Arguments:
  <value>     The variable or value to test
  <begin>     Inclusive lower bound.
  <end>       Inclusive upper bound.

Behavior:
  - All values are parsed as integers or floats automatically.
  - Mixed types (e.g., int + float) are supported (converted to float).
  - Returns true if value ∈ [begin, end].

Examples:
  range 5 1 10
  range 3.14 0.0 3.15
  range $REQ.port 1000 2000
```

## control

### `accept`
```
Perform a control action that terminates the current process chain execution.

Usage: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

Options:
  -h, --help
          Print help


Available Actions:
    drop      Equivalent to `exit drop`. Terminates with result 'drop'.
    accept    Equivalent to `exit accept`. Terminates with result 'accept'.
    reject    Equivalent to `exit reject`. Terminates with result 'reject'.

Notes:
    - All actions immediately stop the entire process chain list.
    - The return value is passed to the outer caller (e.g., dispatcher, protocol stack).
    - Actions are often used after condition expressions such as `match`, `eq`, or `range`.

Examples:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `break`
```
Break the current map-reduce command, optionally with a value.

Usage: break [value]

Arguments:
  [value]
          Optional break value

Options:
  -h, --help
          Print help


Usage:
  break           Break with no value.
  break <value>   Break with the specified string value.

Behavior:
  - Ends execution of the current map-reduce command immediately.
  - Only used to break the current map-reduce command.
  - The return value (if any) is passed to the parent or caller.

Examples:
  break;
  break "map failed"
```

### `drop`
```
Perform a control action that terminates the current process chain execution.

Usage: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

Options:
  -h, --help
          Print help


Available Actions:
    drop      Equivalent to `exit drop`. Terminates with result 'drop'.
    accept    Equivalent to `exit accept`. Terminates with result 'accept'.
    reject    Equivalent to `exit reject`. Terminates with result 'reject'.

Notes:
    - All actions immediately stop the entire process chain list.
    - The return value is passed to the outer caller (e.g., dispatcher, protocol stack).
    - Actions are often used after condition expressions such as `match`, `eq`, or `range`.

Examples:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `error`
```
Return from the current block with error, optionally with a value.

Usage: return [OPTIONS] [value]

Arguments:
  [value]
          Optional return value

Options:
      --from <LEVEL>
          Specifies the execution scope to exit from.
          
          [default: block]
          [possible values: block, chain, lib]

  -h, --help
          Print help


DESCRIPTION:
  Terminates execution at a specified scope with an error status, optionally
  passing a message. This is the primary mechanism for controlling
  exec/return flow.

SCOPE LEVELS (--from):
  block (default): Exits only the current block. Execution continues with the
                   next block in the process-chain. This is the most common use.

  chain: Exits the entire current process-chain. If the chain was invoked via
         `exec --chain`, control and the return value are passed back to the
         caller. If the chain was invoked via `exec --lib`, control returns to the 
         next chain in the library.

  lib:   Exits the entire current library, no matter how deeply nested the
         execution is. If the library was invoked via `exec --lib`, control
         returns to that caller. This is essential for handling early exits
         from complex, nested library calls.

EXAMPLES:
  # Error the current block with no message (default scope)
  error

  # Error the current block with a specific message
  error "invalid input provided"

  # Error the entire process-chain because a required resource is missing
  error --from chain "permission denied to access file"

  # A block deep inside a library needs to terminate the entire library's execution
  error --from lib "not found"
```

### `exec`
```
Execute a block, process-chain, or library by its identifier.

Usage: exec <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>|BLOCK_ID>

Arguments:
  [BLOCK_ID]
          Default: execute a block from the current chain.

Options:
      --block <BLOCK_ID>
          Execute a block by ID.

      --chain <CHAIN_ID>
          Execute a process-chain by ID.

      --lib <LIB_ID>
          Execute a library by ID.

  -h, --help
          Print help


DESCRIPTION:
  Calls a reusable execution unit (block, chain, or lib) and waits for it to
  complete before continuing. The execution unit is found based on its ID
  and the current context.

IDENTIFIER RESOLUTION:
  The ID format determines the search scope for the target unit.

  For --block <ID>:
    - `lib:chain:block`:  Fully qualified. Searches globally for the library,
                          then the chain, then the block.
    - `chain:block`:      Partially qualified. Searches for the chain within the
                          *current library* first, then searches globally.
    - `block`:            Local. Searches for the block within the *current
                          process-chain*.

  For --chain <ID>:
    - `lib:chain`:        Fully qualified. Searches globally for the library,
                          then the chain.
    - `chain`:            Local. Searches for the chain within the *current
                          library* first, then searches globally.

  For --lib <ID>:
    - `lib`:              Global. Searches for the library globally.

EXAMPLES:
  # Execute a block within the current process-chain
  exec --block verify_token

  # Execute a block from a specific chain (searched in the current lib first)
  exec --block auth_flow:get_user_info

  # Execute a block using a fully qualified global ID
  exec --block security_lib:sso_flow:validate_jwt

  # Execute a chain (searched in the current lib first)
  exec --chain user_login_flow

  # Execute a globally unique library
  exec --lib common_utils
```

### `invoke`
```
Invoke a block, process-chain, or library with named arguments.

Usage: invoke [OPTIONS] <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>|BLOCK_ID>

Arguments:
  [BLOCK_ID]
          Default: invoke a block from the current chain.

Options:
      --block <BLOCK_ID>
          Invoke a block by ID.

      --chain <CHAIN_ID>
          Invoke a process-chain by ID.

      --lib <LIB_ID>
          Invoke a library by ID.

      --arg <KEY> <VALUE>
          Named argument for callee, can be repeated.

  -h, --help
          Print help


DESCRIPTION:
  invoke is similar to exec, but it passes named arguments to the callee
  through $__args.<key>.

ARGUMENT PASSING:
  - `--arg <key> <value>` can be repeated.
  - `<value>` can be literal, variable, command substitution, or collection reference.
  - The callee reads arguments via `$__args.<key>`.

EXAMPLES:
  invoke --chain auth_flow --arg user $REQ.user --arg pass $REQ.pass
  invoke --block helper_block --arg req $REQ
```

### `exit`
```
Return from the current process chain list, optionally with a value.

Usage: return [value]

Arguments:
  [value]
          Optional return value

Options:
  -h, --help
          Print help


Usage:
  exit           Exit with no value.
  exit <value>   Exit with the specified string value.

Behavior:
  - Ends execution of the current process chain list to top caller.
  - The return value (if any) is passed to caller.

Examples:
  exit
  exit accept
  exit "invalid input"
```

### `reject`
```
Perform a control action that terminates the current process chain execution.

Usage: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

Options:
  -h, --help
          Print help


Available Actions:
    drop      Equivalent to `exit drop`. Terminates with result 'drop'.
    accept    Equivalent to `exit accept`. Terminates with result 'accept'.
    reject    Equivalent to `exit reject`. Terminates with result 'reject'.

Notes:
    - All actions immediately stop the entire process chain list.
    - The return value is passed to the outer caller (e.g., dispatcher, protocol stack).
    - Actions are often used after condition expressions such as `match`, `eq`, or `range`.

Examples:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `return`
```
Return from the current caller with success, optionally with a value.

Usage: return [OPTIONS] [value]

Arguments:
  [value]
          Optional return value

Options:
      --from <LEVEL>
          Specifies the execution scope to return from.
          
          [default: block]
          [possible values: block, chain, lib]

  -h, --help
          Print help


DESCRIPTION:
  Terminates execution at a specified scope and returns control to the invoker,
  optionally passing a value. This is the primary mechanism for controlling
  exec/return flow.

SCOPE LEVELS (--from):
  block (default): Exits only the current block. Execution continues with the
                   next block in the process-chain. This is the most common use.

  chain: Exits the entire current process-chain. If the chain was invoked via
         `exec --chain`, control and the return value are passed back to the
         caller.

  lib:   Exits the entire current library, no matter how deeply nested the
         execution is. If the library was invoked via `exec --lib`, control
         returns to that caller. This is essential for handling early exits
         from complex, nested library calls.

EXAMPLES:
  # Return from the current block with no value (default scope)
  return

  # Return from the current block with the value "done"
  return done

  # A chain called by `exec --chain` returns its result to the caller
  return --from chain "authentication successful"

  # A block deep inside a library needs to terminate the entire library's execution
  return --from lib "FATAL: configuration missing"
```

## map-reduce

### `map`
```
Perform a map-reduce operation on a collection.

Usage: 
    map --begin <init-cmd> --cmd <map-cmd> [--reduce <reduce-cmd>] <coll>
    map <coll> <map-cmd> reduce <reduce-cmd>
    map <coll> <map-cmd>

Arguments:
  [coll]
          Collection name (required in positional mode)

  [map_cmd]
          Map command in positional mode (required in positional mode)

  [reduce_kw]
          Keyword 'reduce' in positional mode (optional in positional mode)

  [reduce_cmd]
          Reduce command in positional mode (required if 'reduce' is used)

Options:
      --begin <begin>
          Command to run once before processing (optional long mode only)

      --map <map>
          Map command to run for each element (required in long mode)

      --reduce <reduce>
          Reduce command to aggregate results (optional in long mode)

  -h, --help
          Print help


Options:
Long Mode Options:
    --begin <init-cmd>    Command to run once before processing (long mode only)
    --cmd <map-cmd>       Map command to run for each element (required in long mode)
    --reduce <reduce-cmd> Reduce command to aggregate results (optional in long mode)
    -h, --help            Print help
    <coll>                Collection name (required in both mode)

Positional mode Arguments (positional mode):
    <coll>                Collection name (required in both mode)
    <map_cmd>             Map command (required in positional mode)
    <reduce_kw>           Keyword 'reduce' (optional in positional mode)
    <reduce_cmd>          Reduce command (required if 'reduce' is used)

Examples:
  Long mode:
    map --begin $(local sum = "") --map $($sum = append ${key} sum') --reduce $(echo ${sum}) my_coll
  Positional mode:
    map my_coll $($sum = append ${key} sum') reduce $(echo ${sum})
```

## External Commands

### `http-probe`
```
Probe an incoming HTTP stream to extract method, path, version, and host.

Usage: http-probe

Options:
  -h, --help
          Print help


Attempts to probe an incoming plaintext HTTP stream to extract key request line and header information.

Usage:
  http-probe

Behavior:
  - This command reads the beginning of an incoming stream to determine whether it contains a valid HTTP request.
  - If valid, it extracts the following information and updates the environment:
      $REQ.dest_host        ← Host from the `Host:` header
      $REQ.app_protocol     ← "http"
      $REQ.ext.method       ← HTTP method (e.g., GET, POST)
      $REQ.ext.path         ← Request path (e.g., /index.html)
      $REQ.ext.version      ← HTTP version string (e.g., HTTP/1.1)
      $REQ.ext.url          ← Full URL constructed from the host and path
  - Returns success(host) if parsing is successful and a host is found.
  - Returns error if the request is invalid or a Host: header is missing (required for HTTP/1.1).

Requirements:
  - The variable $REQ.incoming_stream must be present in the environment.
    It must be of type AsyncStream.

Examples:
  http-probe && match $REQ.dest_host "api.example.com" && accept
  http-probe && match $REQ.ext.path "/admin/*" && drop
```

### `https-sni-probe`
```
Probe TLS Client Hello SNI

Usage: https-sni-probe

Options:
  -h, --help
          Print help


Attempts to probe the SNI (Server Name Indication) from an incoming TLS stream.

Usage:
  https-sni-probe

Behavior:
  - This command inspects the beginning of an incoming stream to determine whether
    it is a valid HTTPS connection.
  - If the connection is HTTPS and contains a valid SNI field, the SNI hostname will
    be extracted and used to update the environment as follows:
      $REQ.dest_host     ← extracted hostname
      $REQ.app_protocol  ← "https"
  - Returns success(host) if an SNI hostname is successfully parsed.
  - Returns error if the connection is not HTTPS or no SNI is found.

Requirements:
  - The variable $REQ.incoming_stream must be present in the environment.
    It must be of type AsyncStream.

Examples:
  https-sni-probe && accept
```
