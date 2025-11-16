# Command reference documentation

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
          Target collection variable name

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
    match-include $HOST $REQ_host "www.test.com" && drop
    match-include $IP $REQ_ip "127.0.0.1" "192.168.100.1" && accept
```

### `set-add`
```
Add a value to a set collection.

Usage: set-add <set_id> <value>

Arguments:
  <set_id>
          The ID of the target set

  <value>
          The value to insert into the set

Options:
  -h, --help
          Print help


Arguments:
  <set_id>    The identifier of the target set.
  <value>     The value to insert into the set.

Notes:
  - If the set does not exist, the operation fails.
  - Sets only store unique values.
  - Use `set-create` to initialize a set before using this command.

Examples:
  set-add trusted_hosts "192.168.1.1"
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

Usage: set-remove <set_id> <value>

Arguments:
  <set_id>
          The ID of the set to remove from

  <value>
          The value to remove

Options:
  -h, --help
          Print help


Arguments:
  <set_id>    The identifier of the target set.
  <value>     The value to remove from the set.

Notes:
  - If the set does not exist, the operation fails.
  - If the value is not in the set, it is ignored.
  - Sets only store unique values.

Examples:
  set-remove trusted_hosts "192.168.1.1"
  set-remove temp_set "flag_enabled"
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

Examples:
    my_var=123
    global my_var=456
    block my_var
```

## string

### `append`
```
Append two string parameters and return the result.

Usage: append <param1> <param2>

Arguments:
  <param1>
          First value

  <param2>
          Second value to append

Options:
  -h, --help
          Print help


Arguments:
  <param1>     First string or variable
  <param2>     Second string to append

Behavior:
  - Joins param1 and param2 with no delimiter.
  - Output is returned with success.
  - The command will not modify any env variables 

Examples:
  append "abc" "123"
  append $REQ.host ".internal"
```

### `ends-with`
```
Check if a string ends with the given suffix.

Usage: ends-with <string> <suffix>

Arguments:
  <string>
          Input string to check

  <suffix>
          Suffix to test against

Options:
  -h, --help
          Print help


Arguments:
  <string>   The full input string.
<suffix>     The suffix to check.
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
  --ignore-case   Perform case-insensitive comparison

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

Usage: starts-with <string> <prefix>

Arguments:
  <string>
          Input string to check

  <prefix>
          Prefix to test against

Options:
  -h, --help
          Print help


Arguments:
  <string>     The full input string.
  <prefix>     The prefix to check.

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

Usage: return [value]

Arguments:
  [value]
          Optional return value

Options:
  -h, --help
          Print help


Usage:
  error           Return with no value.
  error <value>   Return the specified string value.

Behavior:
  - Ends execution of the current block immediately with error.
  - The return value (if any) is passed to the parent or caller.
  - Used for control flow inside process chain blocks.

Examples:
  error
  error ok
  error "invalid input"
```

### `exec`
```
Execute a block by its identifier within the current process chain.

Usage: exec <block_id>

Arguments:
  <block_id>
          The ID of the block to execute

Options:
  -h, --help
          Print help


Arguments:
  <block_id>    The ID of the block to execute.

Behavior:
  - The specified block must exist in the current process chain.
  - The block will be executed immediately, and its result is returned.
  - Execution then continues with the next command in the current block.
  - If the block does not exist, an error will occur.

Examples:
  exec verify_token
  exec block_login && drop
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

### `goto`
```
Jump to a block or another chain within the process flow.

Usage: goto [OPTIONS] <target>

Arguments:
  <target>
          The name of the target block or chain

Options:
      --chain
          Jump to another chain

      --block
          Jump to a block in the current chain (default)

  -h, --help
          Print help


Arguments:
  <target>     The name of the target block or chain.

Options:
  --chain      Jump to a chain by name (default).
  --block      Jump to a block in the current chain.

Behavior:
  - Without options, defaults to jumping to a chain.
  - When using `--chain`, execution switches to the specified chain.
  - When using `--block`, jumps to a block inside the current chain.
  - The next command of the current command will not be executed any more.
  - Fails if the target block/chain does not exist.

Examples:
  goto login_retry
  goto --block validate_input
  goto --chain fallback_chain
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
Return from the current block with success, optionally with a value.

Usage: return [value]

Arguments:
  [value]
          Optional return value

Options:
  -h, --help
          Print help


Usage:
  return           Return with no value.
  return <value>   Return the specified string value.

Behavior:
  - Ends execution of the current block immediately with success.
  - The return value (if any) is passed to the parent or caller.
  - Used for control flow inside process chain blocks.

Examples:
  return
  return ok
  return "user input accepted"
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

## 一些常见的内置对象

### REQ
- REQ.dest_port
- REQ.dest_host
- REQ.protocol udp | tcp
- REQ.app_protocl
- REQ.dest_url
- REQ.source_addr
- REQ.source_mac
- REQ.source_device_id
- REQ.source_app_id
- REQ.source_user_id



### RESP


### ANSWER

