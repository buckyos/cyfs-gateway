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
  <pattern>   A case-insensitive glob pattern to match
  <template>  The replacement string or trailing-* template

Behavior:
  - Performs case-insensitive glob pattern matching.
  - If <pattern> does not match, returns error and leaves the variable unchanged.
  - If <pattern> ends with '*' and <template> also ends with '*', preserves the
    matched suffix by appending it to <template> without its trailing '*'.
  - Otherwise, if <pattern> matches, rewrites the variable to <template> as-is.

Examples:
  rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
  rewrite $REQ.host "*.example.com" "backend.internal"
```

### `rewrite-reg`
```
Rewrite a variable using a regular expression and a replacement template.

Usage: rewrite-reg <var> <regex> <template>

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
  - Only '$' followed by one ASCII digit is treated as a capture reference.
    Other '$' characters are kept literally.
  - Unmatched captures are replaced with empty strings.
  - If the pattern does not match, returns error and leaves the variable unchanged.

Examples:
  rewrite-reg $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
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

### Variable Path, Safe Access, and Default
```
These are DSL expression rules for variable arguments (not a standalone command).

Supported forms:
  - Basic path:
      $REQ.clientIp
      ${REQ.clientIp}

  - Bracket path:
      $geoByIp[$REQ.clientIp]
      ${geoByIp["1.2.3.4"].country}

  - Optional/safe access:
      ${geoByIp[$REQ.clientIp]?.country}
      $geoByIp[$REQ.clientIp]?.meta?.["region.code"]

  - Coalesce default:
      ${geoByIp[$REQ.clientIp]?.country ?? "unknown"}
      $geoByIp[$REQ.clientIp]?.country??$REQ.defaultCountry

Semantics:
  - `?.` / `?[...]` mark the following segment as optional.
  - Optional segment missing or type mismatch does not trigger strict missing-var error.
  - Optional missing without `??` yields empty string.
  - `??` only applies when left side is missing.
  - If left side exists, right side is not evaluated.

Default RHS support:
  - Supported: string literal, variable expression.
  - Not supported yet: command substitution `$(...)` on RHS of `??`.
```

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
          Variable name to store CommandResult payload (typed value)

      --status <VAR>
          Variable name to store status: success|error|control

      --ok <VAR>
          Variable name to store bool: result is success

      --error <VAR>
          Variable name to store bool: result is error

      --control <VAR>
          Variable name to store bool: result is control

      --control-kind <VAR>
          Variable name to store control kind: return|error|exit|break; Null if not control

      --from <VAR>
          Variable name to store control level: block|chain|lib; Null if not return/error control

  -h, --help
          Print help


Examples:
  capture --value geo --status st --ok ok $(lookup-geo $clientIp)
  capture --value out $(call check_something $arg)
  capture --status st --control ctl --control-kind kind --from from $(some-command)

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

### `is-bool`
```
Check whether a value is Bool.

Usage: is-bool <value>

Arguments:
  <value>
          Value to inspect

Options:
  -h, --help
          Print help
```

### `is-null`
```
Check whether a value is Null.

Usage: is-null <value>

Arguments:
  <value>
          Value to inspect

Options:
  -h, --help
          Print help
```

### `is-number`
```
Check whether a value is Number.

Usage: is-number <value>

Arguments:
  <value>
          Value to inspect

Options:
  -h, --help
          Print help
```

### `to-bool`
```
Convert a value to bool according to execution coercion policy.

Usage: to-bool <value>

Arguments:
  <value>
          Value to convert

Options:
  -h, --help
          Print help
```

### `to-number`
```
Convert a value to number according to execution coercion policy.

Usage: to-number <value>

Arguments:
  <value>
          Value to convert

Options:
  -h, --help
          Print help
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

### `list-clear`
```
Clear all values from a list collection.

Usage: list-clear <list_id>

Arguments:
  <list_id>
          The ID of the target list

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.

Examples:
  list-clear request_history
```

### `list-create`
```
Create a new list collection with a given identifier and scope.

Usage: list-create [OPTIONS] <list_id>

Arguments:
  <list_id>
          The ID of the list to create

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
  <list_id>   The identifier of the list collection to create.

Scope Options:
  -global, -export    Create the list in the global scope.
  -chain              Create the list in the current process chain scope (default).
  -block, -local      Create the list in the current execution block (local) scope.

Notes:
  - If no scope is specified, the default is chain-level.

Examples:
  list-create -global request_history
  list-create session_steps
  list-create -block temp_values
```

### `list-insert`
```
Insert a value into a list collection at a specific index.

Usage: list-insert <list_id> <index> <value>

Arguments:
  <list_id>
          The ID of the target list

  <index>
          Zero-based index

  <value>
          The value to insert

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.
  <index>     Zero-based index to insert at.
  <value>     Value to insert.

Examples:
  list-insert request_history 0 "begin"
  list-insert records 1 $REQ
```

### `list-pop`
```
Pop the last value from a list collection.

Usage: list-pop <list_id>

Arguments:
  <list_id>
          The ID of the target list

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.

Examples:
  list-pop request_history
```

### `list-push`
```
Append one or more values to a list collection.

Usage: list-push <list_id> <value>...

Arguments:
  <list_id>
          The ID of the target list

  <value>...
          One or more values to append to the list

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.
  <value>...  One or more values to append.

Examples:
  list-push request_history "step1" "step2"
  list-push records $REQ
```

### `list-remove`
```
Remove a value from a list collection at a specific index.

Usage: list-remove <list_id> <index>

Arguments:
  <list_id>
          The ID of the target list

  <index>
          Zero-based index

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.
  <index>     Zero-based index to remove.

Examples:
  list-remove request_history 0
```

### `list-set`
```
Set a value in a list collection at a specific index.

Usage: list-set <list_id> <index> <value>

Arguments:
  <list_id>
          The ID of the target list

  <index>
          Zero-based index

  <value>
          The value to set

Options:
  -h, --help
          Print help


Arguments:
  <list_id>   The identifier of the target list.
  <index>     Zero-based index to replace.
  <value>     New value.

Examples:
  list-set request_history 0 "start"
  list-set records 2 $REQ
```

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
Compare two values for equality (strict typed by default).

Usage: eq [OPTIONS] <value1> <value2>

Arguments:
  <value1>
          The first value to compare

  <value2>
          The second value to compare

Options:
  -i, --ignore-case
          Enable case-insensitive comparison (string-string only)

  -l, --loose
          Enable loose comparison for string/number

  -h, --help
          Print help


Compare two values for equality.

Arguments:
  <value1>        First value to compare
  <value2>        Second value to compare

Options:
  --ignore-case   Perform case-insensitive comparison (string-string only)
  --loose         Enable loose comparison for string/number

By default, eq uses strict typed comparison:
  - Same-type scalar values are compared directly
  - Different types are not equal (e.g. Number(1) != String("1"))

Syntax sugar:
  - value1 == value2   => eq --loose value1 value2
  - value1 === value2  => eq value1 value2
  - Mainly used in if/elif conditions for readability.

Examples:
  eq 1 1
  eq 1 "1"              # false under strict mode
  eq --loose 1 "1"      # true under loose mode
  if $REQ.port == "443" then ...
  if $REQ.role === "admin" then ...
  eq "host" "host"
  eq --ignore-case "Host" "HOST"
```

### `ne`
```
Compare two values for inequality (strict typed by default).

Usage: ne [OPTIONS] <value1> <value2>

Options:
  -i, --ignore-case   Case-insensitive for string-string only
  -l, --loose         Enable loose comparison for string/number

Syntax sugar:
  - value1 != value2   => ne --loose value1 value2
  - value1 !== value2  => ne value1 value2
  - Mainly used in if/elif conditions for readability.

Examples:
  ne 1 "1"                 # true under strict mode
  ne --loose 1 "1"         # false under loose mode
  ne --ignore-case "A" "a" # false
  if $REQ.port != "443" then ...
  if $REQ.role !== "admin" then ...
```

### `gt` / `ge` / `lt` / `le`
```
Numeric comparison commands.

Usage:
  gt [OPTIONS] <value1> <value2>   # value1 > value2
  ge [OPTIONS] <value1> <value2>   # value1 >= value2
  lt [OPTIONS] <value1> <value2>   # value1 < value2
  le [OPTIONS] <value1> <value2>   # value1 <= value2

Options:
  -l, --loose    Enable loose number parsing for string/number

Behavior:
  - Strict mode: only Number values are comparable.
  - Loose mode: String/Number mixed comparison is allowed if string is numeric.
  - Non-comparable values return false.

Syntax sugar (strict mode):
  - value1 > value2   => gt value1 value2
  - value1 >= value2  => ge value1 value2
  - value1 < value2   => lt value1 value2
  - value1 <= value2  => le value1 value2
  - If loose parsing is needed, use explicit commands: gt/ge/lt/le --loose ...

Examples:
  gt 10 9
  ge --loose "2" 2
  lt --loose "1.5" 2
  if $REQ.port >= 443 then ...
  if $latency_ms < 100 then ...
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

### `goto`
```
Tail-transfer to a block/chain/lib and then return from a chosen scope.

Usage: goto [OPTIONS] <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>>

Options:
      --block <BLOCK_ID>
          Transfer to a block by ID.

      --chain <CHAIN_ID>
          Transfer to a process-chain by ID.

      --lib <LIB_ID>
          Transfer to a library by ID.

      --from <LEVEL>
          Default return/error scope after target execution. Values: block|chain|lib.

      --ok-from <LEVEL>
          Success return scope override. Values: block|chain|lib.

      --err-from <LEVEL>
          Error return scope override. Values: block|chain|lib.

      --arg <KEY> <VALUE>
          Named argument for target, can be repeated.

  -h, --help
          Print help


DESCRIPTION:
  goto is a structured tail-transfer command. It first executes the target
  (same semantics as invoke), then maps result to return/error from the
  selected caller scope.

TARGET ID FORMAT:
  Same as exec/invoke:
  - --block: block | chain:block | lib:chain:block
  - --chain: chain | lib:chain
  - --lib: lib

RETURN LEVEL:
  - `--from` sets the common default for success/error mapping.
  - `--ok-from` overrides success mapping scope.
  - `--err-from` overrides error mapping scope.
  - If all are omitted, defaults to `block` (same as `return`/`error` without `--from`).

RESULT MAPPING:
  - target success(value) -> return --from <ok-level> value
  - target error(value)   -> error  --from <err-level> value

NOTES:
  - This is not a low-level instruction pointer jump.
  - Statements after goto in the same execution path will not be executed.

EXAMPLES:
  goto --chain fallback_chain
  goto --chain auth_flow --from lib
  goto --chain auth_flow --from chain --err-from lib
  goto --chain auth_flow --ok-from lib --err-from chain
  goto --block helper --arg req $REQ
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

## statements

### Structured Statement Overview
```
These are DSL syntax forms, not standalone commands. They are parsed at the
statement level, so they do not appear in the command registry.
```

### `if` / `elif` / `else` / `end`
```
Branch on a boolean/predicate condition.

Syntax:
  if <condition> then
      ...
  elif <condition> then
      ...
  else
      ...
  end

Supported condition styles:
  - Predicate command:
      if eq $REQ.role "admin" then
  - Negated predicate command:
      if !eq $REQ.protocol "https" then
  - Infix comparison sugar:
      if $one == "1" then
      if $one === "1" then
      if $one != "1" then
      if $one !== "1" then
      if $one > 0 then
      if $one >= 1 then
      if $one < 2 then
      if $one <= 1 then

Notes:
  - `==` / `!=` use loose comparison semantics.
  - `===` / `!==` use strict typed comparison semantics.
  - Missing `end` is a parse/link error.
```

### `for ... in ... then ... end`
```
Traverse a collection with structured loop semantics.

Syntax:
  for item in $list then
      ...
  end

  for idx, item in $list then
      ...
  end

  for item in $set then
      ...
  end

  for key, value in $map then
      ...
  end

  for key, values in $multi_map then
      ...
  end

Behavior:
  - Loop variables are local to the for-block.
  - Outer variables with the same name are restored after the loop ends.
  - `break [value]` exits only the current loop.
  - `return` / `error` / `exit` / `goto` continue to propagate normally.

Traversal safety:
  - Mutating the same collection while it is being traversed is rejected.
  - This applies to list/set/map/multi-map traversal.

Examples:
  for item in $values then
      eq $item "b" && break "stop";
  end

  for key, value in $routes then
      map-add copied $key $value;
  end

  for key, values in $tags then
      for item in $values then
          echo $key $item;
      end
  end
```

### `match-result`
```
Execute one command substitution once, then branch by CommandResult kind.

Syntax:
  match-result $(<command>)
  ok(value)
      ...
  err(err_value)
      ...
  control(action, from, value)
      ...
  end

Rules:
  - The input must be a single command substitution: `$(...)`.
  - `ok(...)` handles Success(value).
  - `err(...)` handles Error(value).
  - `control(action, from, value)` handles Control results.
  - Unhandled result kinds propagate unchanged.

Examples:
  match-result $(append "hello" "_ok")
  ok(value)
      return --from lib $(append "handled:" $value);
  end

  match-result $(match "abc" "z*")
  err(err_value)
      eq $err_value false || return --from lib "bad_err_value";
      return --from lib "handled_error";
  end

  match-result $(return --from chain "chain_value")
  control(action, from, value)
      eq $action "return" || return --from lib "bad_action";
      eq $from "chain" || return --from lib "bad_from";
      return --from lib "handled_control";
  end
```
