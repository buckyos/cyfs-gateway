# 命令参考文档（中文）

> 说明：命令名、选项名、变量写法与脚本语法关键字保持英文；以下内容主要对说明文字做中文化，便于中文读者查阅。

## string 字符串

### `append`
```
拼接两个或更多字符串参数，并返回结果。

用法: append <params> <params>...

参数:
  <params> <params>...
          两个或更多要拼接的值

选项:
  -h, --help
          显示帮助


参数:
  <params>...  两个或更多要拼接的字符串或变量

行为:
  - 将所有参数直接拼接，不插入分隔符。
  - 结果以 success 返回。
  - 除非另有说明，此命令不会修改环境变量。

示例:
  append "abc" "123"
  append $REQ.host ".internal" ".com"
  append "prefix-" $VAR "-suffix"
```

### `ends-with`
```
检查字符串是否以给定后缀结尾。

用法: ends-with [OPTIONS] <string> <suffix>

参数:
  <string>
          要检查的输入字符串

  <suffix>
          要匹配的后缀

选项:
  -i, --ignore-case
          执行大小写不敏感比较

  -h, --help
          显示帮助


参数:
  <string>   完整输入字符串。
  <suffix>   要检查的后缀。

选项:
  --ignore-case,-i   执行大小写不敏感比较

行为:

  - 如果 <string> 以 <suffix> 结尾，则返回 true。
  - 默认区分大小写。
  - 不会修改任何变量或环境。

示例:
  ends-with "hello world" "world"       → true
  ends-with $REQ.url ".html"            → false
  ends-with "example.com" ".com"        → true
```

### `replace`
```
替换变量值中所有出现的指定子串。

用法: replace [OPTIONS] <var> <match> <replacement>

参数:
  <var>
          要修改的变量名

  <match>
          要搜索的文本

  <replacement>
          替换成的文本

选项:
  -i, --ignore-case
          执行大小写不敏感比较

  -h, --help
          显示帮助


参数:
  <var>         要修改的变量名，例如 $REQ.host
  <match>       要搜索的子串
  <replacement> 替换字符串

选项:
  --ignore-case,-i   执行大小写不敏感比较

行为:
  - 将所有不重叠的 <match> 替换为 <replacement>。
  - 默认区分大小写。
  - 如果未找到 <match>，变量保持不变。

示例:
  replace $REQ.host "io" "ai"
  replace $PATH "/old/" "/new/"
```

### `rewrite`
```
使用 glob 模式重写变量的值。

用法: rewrite <var> <pattern> <template>

参数:
  <var>
          要重写的变量名

  <pattern>
      要匹配的 glob 模式

  <template>
      替换模板

选项:
  -h, --help
          显示帮助


参数:
  <var>       要重写的变量，例如 $REQ.url
  <pattern>   以大小写不敏感方式匹配的 glob 模式
  <template>  替换字符串，或以 `*` 结尾的后缀透传模板

行为:
  - 以大小写不敏感方式执行 glob 匹配。
  - 如果 <pattern> 未匹配，则返回 error，且变量保持不变。
  - 如果 <pattern> 以 `*` 结尾且 <template> 也以 `*` 结尾，则保留匹配到的后缀，
    并把该后缀追加到去掉末尾 `*` 的模板后面。
  - 否则，只要 <pattern> 匹配成功，就直接把变量重写为 <template> 当前求值结果。

示例:
  rewrite $REQ.url "/kapi/my-service/*" "/kapi/*"
  rewrite $REQ.host "*.example.com" "backend.internal"
```

### `rewrite-reg`
```
使用正则表达式与替换模板重写变量。

用法: rewrite-reg <var> <regex> <template>

参数:
  <var>
          要重写的变量

  <regex>
          正则表达式模式

  <template>
      替换模板

选项:
  -h, --help
          显示帮助


参数:
  <var>        要重写的变量名，例如 $REQ.url
  <regex>      用于匹配的正则表达式，可带捕获组
  <template>   替换字符串，可使用 $1、$2 等引用捕获组

行为:
  - 如果正则匹配成功，则按模板重写变量值。
  - 只有 `$` 后紧跟 1 位 ASCII 数字时，才会被当作捕获组引用；
    其他 `$` 都按普通字符保留。
  - 未匹配到的捕获组会替换为空字符串。
  - 如果未匹配成功，则返回 error，且变量保持不变。

示例:
  rewrite-reg $REQ.url "^/test/(\\w+)(?:/(\\d+))?" "/new/$1/$2"
```

### `slice`
```
按字节范围截取字符串并返回结果。

用法: slice <string> <range>

参数:
  <string>
          要切片的字符串

  <range>
          切片范围，格式为 start:end

选项:
  -h, --help
          显示帮助


参数:
  <string>       要截取的输入字符串或变量。
  <start:end>    字节索引范围，结束位置为排他。

行为:
  - 使用 UTF-8 安全的按字节切片逻辑。
  - 返回从 `start` 开始、到 `end` 之前结束的子串。
  - 如果 end 小于或等于 start，则返回空字符串。
  - 不会修改任何变量或环境。

示例:
  slice "abcdef" 1:4
  slice $REQ.url 0:10
```

### `starts-with`
```
检查字符串是否以给定前缀开头。

用法: starts-with [OPTIONS] <string> <prefix>

参数:
  <string>
          要检查的输入字符串

  <prefix>
          要匹配的前缀

选项:
  -i, --ignore-case
          执行大小写不敏感比较

  -h, --help
          显示帮助


参数:
  <string>     完整输入字符串。
  <prefix>     要检查的前缀。

选项:
  --ignore-case,-i   执行大小写不敏感比较

行为:
  - 如果 <string> 以 <prefix> 开头，则返回 true。
  - 默认区分大小写。
  - 不会修改任何变量或环境。

示例:
  starts-with "hello world" "hello"     → true
  starts-with $REQ.url "/api/"          → true
  starts-with "example.com" "test"      → false
```

### `split`
```
使用分隔符把字符串拆分成多个片段。

用法: split [OPTIONS] <value> <delimiter>

参数:
  <value>
          待拆分的输入字符串

  <delimiter>
          用于拆分的分隔符字符串

选项:
      --capture <name>
          把拆分结果写入一个新的 List 变量

      --skip-empty
          丢弃空片段

  -h, --help
          显示帮助


参数:
  <value>       输入字符串或变量。
  <delimiter>   用于拆分输入的分隔符字符串。

选项:
  --capture <name>   把片段写入一个新的 List 变量，可通过 name[0]、name[1]... 访问
  --skip-empty       从返回结果和 capture 槽位中都移除空片段

行为:
  - 两个参数都在运行时动态求值。
  - 返回一个由字符串片段组成的 List。
  - 默认保留空片段，包括开头或结尾产生的空片段。
  - 指定 --skip-empty 后，会同时从返回的 List 和 capture 槽位中移除空片段。
  - 指定 --capture 后，会用一个新的 List 替换 <name>，其中包含拆分得到的所有片段。
  - <name> 必须是字面量变量名或变量路径。
  - 空分隔符是非法输入，会返回运行时错误。

示例:
  split "/a/b/c" "/"
  split --skip-empty "/.cluster/klog/ood1/admin/" "/"
  split --capture parts $REQ.path $delimiter
```

### `strip-prefix`
```
移除字符串前缀并返回剩余 tail。

用法: strip-prefix [OPTIONS] <value> <prefix>

参数:
  <value>
          要处理的输入字符串

  <prefix>
          要移除的前缀

选项:
  -i, --ignore-case
          执行大小写不敏感比较

  -h, --help
          显示帮助


参数:
  <value>      完整输入字符串或变量。
  <prefix>     要移除的前缀。

行为:
  - 两个参数都在运行时动态求值。
  - 如果 <value> 以 <prefix> 开头，则 success 返回剩余 tail。
  - 如果 <value> 与 <prefix> 完全相等，则 success 返回空字符串。
  - 默认区分大小写。
  - 如果 <value> 不以 <prefix> 开头，则返回 error，且原值不变。
  - 不会修改任何变量或环境。

示例:
  strip-prefix "/api/v1/users" "/api"
  strip-prefix --ignore-case "/API/v1/users" "/api"
  strip-prefix $REQ.url $route_prefix
```

### `strlen`
```
返回字符串长度。

用法: strlen <string>

参数:
  <string>
          要计算长度的输入字符串

选项:
  -h, --help
          显示帮助


参数:
  <string>     要计算长度的输入字符串。

行为:
  - 返回字符长度。
  - 不会修改环境或变量。

示例:
  strlen "abc"
  strlen "你好"
  strlen $REQ.path
```

## debug 调试

### `echo`
```
显示一行文本，或输出给定参数。

用法: echo [OPTIONS] [args]...

参数:
  [args]...
          要显示的文本参数

选项:
  -n
          不输出末尾换行

  -v, --verbose
          输出更多命令执行信息，例如集合内容

  -h, --help
          显示帮助


选项:
  -n          不输出末尾换行.
  --verbose   输出更多命令执行信息，例如集合内容。

行为:
  - 用空格拼接所有参数并输出。
  - 默认在末尾追加换行。

示例:
  echo "Hello, World!";
  echo -n "Hello," "World!";
  echo --verbose $REQ;
```

## variable 变量

### 变量路径、安全访问与默认值
```
这些是变量参数使用时的 DSL 表达式规则，不是独立命令。

支持的形式:
  - 基础路径:
      $REQ.clientIp
      ${REQ.clientIp}

  - 下标路径:
      $geoByIp[$REQ.clientIp]
      ${geoByIp["1.2.3.4"].country}
      $records[0].name
      $matrix[1][0]

  - 可选 / 安全访问:
      ${geoByIp[$REQ.clientIp]?.country}
      $geoByIp[$REQ.clientIp]?.meta?.["region.code"]

  - 缺省合并:
      ${geoByIp[$REQ.clientIp]?.country ?? "unknown"}
      $geoByIp[$REQ.clientIp]?.country??$REQ.defaultCountry

语义:
  - `?.` / `?[...]` 表示后续路径段为可选访问。
  - 下标路径同时支持 map key 和 list 下标。
  - 可选路径段缺失，或类型不匹配时，不会触发严格 missing-var 错误。
  - 如果可选访问缺失且没有 `??`，则结果为空字符串。
  - `??` 只在左侧值缺失时生效。
  - 如果左侧值存在，则不会计算右侧表达式。

默认值右侧支持:
  - 已支持：字符串字面量、变量表达式。
  - 尚不支持：`??` 右侧直接使用命令替换 `$(...)`。
```

### `assign`
```
管理变量定义与默认作用域偏好。

用法: 
  [SCOPE] VAR=VALUE     在指定作用域中定义或更新变量。
  VAR=VALUE             在默认（chain）作用域中定义变量。
  SCOPE VAR             为后续对 VAR 的引用设置默认查找作用域。

选项:
  -h, --help
          显示帮助


作用域:
    export, global        全局作用域（跨链共享）
    chain                 链级作用域（默认）
    block, local          块级作用域

说明:
    - 如果变量已存在，其值会被覆盖。
    - 赋值形式（VAR=VALUE）在未显式指定时默认落到 `chain` 作用域。
    - 仅写 `SCOPE VAR` 时，表示为 VAR 设置默认查找作用域。
    - 右侧不仅支持字符串，也支持非字符串值，例如 Map/Set/MultiMap。
    - 集合赋值使用引用语义（共享引用），不是深拷贝。
      执行 `a=$b` 后，通过 `a` 和 `b` 的修改彼此可见。

示例:
    my_var=123
    global my_var=456
    block my_var
    local currentGeo=$geoByIp[$REQ.clientIp]
    local trustedSet=$trustedCountrySet
```

### `capture`
```
执行一次子命令，将其结果值/状态捕获到本地变量中，并返回原始结果。

用法: capture [OPTIONS] <command>

参数:
  <command>
          子命令，必须使用命令替换形式：$(...)

选项:
      --value <VAR>
          用于存储 CommandResult 载荷（typed value）的变量名

      --status <VAR>
          用于存储状态 success|error|control 的变量名

      --ok <VAR>
          用于存储布尔值：结果是否为 success 的变量名

      --error <VAR>
          用于存储布尔值：结果是否为 error 的变量名

      --control <VAR>
          用于存储布尔值：结果是否为 control 的变量名

      --control-kind <VAR>
          用于存储控制类型的变量名：return|error|exit|break；若不是 control 则为 Null

      --from <VAR>
          用于存储控制层级的变量名：block|chain|lib；若不是 return/error control 则为 Null

  -h, --help
          显示帮助


示例:
  capture --value geo --status st --ok ok $(lookup-geo $clientIp)
  capture --value out $(call check_something $arg)
  capture --status st --control ctl --control-kind kind --from from $(some-command)

说明:
  - 子命令必须使用命令替换形式传入：`$(...)`。
  - 捕获出的变量会写入 block(local) 作用域。
  - 此命令会原样返回子命令的 CommandResult，不做改写。
```

### `delete`
```
从指定作用域删除变量或集合中的值。

用法: delete [--global|--chain|--block] <variable_name>

参数:
  <variable_name>
          要删除的变量名

选项:
      --global
          使用全局作用域

      --chain
          使用链级作用域（默认）

      --block
          使用块（local）作用域

  -h, --help
          显示帮助


从指定作用域中删除变量或集合值。

作用域选项:
  --export, --global   全局作用域
  --chain              链级作用域
  --block, --local     块级作用域

变量名:
  - 变量名可以包含点分路径，用于访问嵌套值，
    尤其适用于 set/map/multimap 这类结构化集合。
  - 例如：$REQ.header、$REQ.headers.Host、$USER.config.theme
  - 如果未指定作用域，则默认使用变量当前所在的作用域。

删除模式:
  - 如果完整名称指向顶层变量（例如 $REQ、$temp），则会从给定作用域中删除整个变量。
  - 如果名称包含路径（例如 REQ.header1），则会尝试从容器 `REQ` 中删除 `header1` 这个 key。

示例:
  delete my_var;
  delete --global user_token;
  delete --block tmp_value;
  delete $REQ.header1;
```

### `is-bool`
```
检查一个值是否为 Bool。

用法: is-bool <value>

参数:
  <value>
          待检查的值

选项:
  -h, --help
          显示帮助
```

### `is-null`
```
检查一个值是否为 Null。

用法: is-null <value>

参数:
  <value>
          待检查的值

选项:
  -h, --help
          显示帮助
```

### `is-number`
```
检查一个值是否为 Number。

用法: is-number <value>

参数:
  <value>
          待检查的值

选项:
  -h, --help
          显示帮助
```

### `to-bool`
```
根据执行期 coercion policy 将值转换为 bool。

用法: to-bool <value>

参数:
  <value>
          待转换的值

选项:
  -h, --help
          显示帮助
```

### `to-number`
```
根据执行期 coercion policy 将值转换为 number。

用法: to-number <value>

参数:
  <value>
          待转换的值

选项:
  -h, --help
          显示帮助
```

### `type`
```
判断并显示给定参数的类型。

用法: type [OPTIONS] <variable_name>

参数:
  <variable_name>
          要获取类型的变量名

选项:
      --global
          使用全局作用域

      --chain
          使用链级作用域（默认）

      --block
          使用块（local）作用域

  -h, --help
          显示帮助


获取给定变量或集合值的类型。

作用域选项:
  --export, --global   全局作用域
  --chain              链级作用域
  --block, --local     块级作用域

行为:
  - 计算参数并识别其类型。
  - 如果目标变量存在，则返回 success(type string)。
  - 如果目标变量不存在，则返回 error("None")。
  - 如果未显式指定作用域，则默认使用变量当前作用域；若没有则默认 chain 级。

示例:
    type my_var
    type --global $my_var
    type --block my_map.key
```

## external 外部调用

### `call`
```
调用外部命令或用户自定义命令，并传递参数

用法: call <command> [args]...

参数:
  <command>
          要执行的外部命令

  [args]...
          外部命令参数

选项:
  -h, --help
          显示帮助


说明:
  - 所有 external command 都必须先在运行时注册。
  - 如果命令不存在，则返回 error。
  - 该命令适合调用插件式或用户自定义逻辑，避免污染内部命令命名空间。

示例:
  call verify_token $REQ.token
  call user_lookup alice
  call plugin.process_json '{"key": "value"}'
```

## collection 集合

### `list-clear`
```
清空 list 集合中的所有值。

用法: list-clear <list_id>

参数:
  <list_id>
          目标 list 的 ID

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。

示例:
  list-clear request_history
```

### `list-create`
```
按给定标识符与作用域创建新的 list 集合。

用法: list-create [OPTIONS] <list_id>

参数:
  <list_id>
          要创建的 list 的 ID

选项:
      --global
          使用全局作用域
          
          [aliases: --export]

      --chain
          使用链级作用域（默认）

      --block
          使用块级作用域
          
          [aliases: --local]

  -h, --help
          显示帮助


参数:
  <list_id>   要创建的 list 集合标识符。

作用域选项:
  -global, -export    在全局作用域创建 list。
  -chain              在当前 process chain 作用域创建 list（默认）。
  -block, -local      在当前执行块（local）作用域创建 list。

说明:
  - 如果未指定作用域，则默认使用 chain 级作用域。

示例:
  list-create -global request_history
  list-create session_steps
  list-create -block temp_values
```

### `list-insert`
```
在 list 集合的指定索引处插入一个值。

用法: list-insert <list_id> <index> <value>

参数:
  <list_id>
          目标 list 的 ID

  <index>
          从 0 开始的索引

  <value>
          要插入的值

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。
  <index>     要插入的位置，从 0 开始计数。
  <value>     要插入的值。

示例:
  list-insert request_history 0 "begin"
  list-insert records 1 $REQ
```

### `list-pop`
```
弹出 list 集合中的最后一个值。

用法: list-pop <list_id>

参数:
  <list_id>
          目标 list 的 ID

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。

示例:
  list-pop request_history
```

### `list-push`
```
向 list 集合尾部追加一个或多个值。

用法: list-push <list_id> <value>...

参数:
  <list_id>
          目标 list 的 ID

  <value>...
          一个或多个要追加到 list 的值

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。
  <value>...  一个或多个要追加的值。

示例:
  list-push request_history "step1" "step2"
  list-push records $REQ
```

### `list-remove`
```
删除 list 集合指定索引处的值。

用法: list-remove <list_id> <index>

参数:
  <list_id>
          目标 list 的 ID

  <index>
          从 0 开始的索引

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。
  <index>     要删除的位置，从 0 开始计数。

示例:
  list-remove request_history 0
```

### `list-set`
```
设置 list 集合指定索引处的值。

用法: list-set <list_id> <index> <value>

参数:
  <list_id>
          目标 list 的 ID

  <index>
          从 0 开始的索引

  <value>
          要设置的值

选项:
  -h, --help
          显示帮助


参数:
  <list_id>   目标 list 的标识符。
  <index>     要替换的位置，从 0 开始计数。
  <value>     新值。

示例:
  list-set request_history 0 "start"
  list-set records 2 $REQ
```

### `map-add`
```
向 map 或 multimap 集合中添加或更新键值对。

用法: map-add <map_id> <key> <values>...

参数:
  <map_id>
          目标 map 集合的 ID

  <key>
          要插入或更新的 key

  <values>...
          一个或多个要关联到该 key 的值

选项:
  -h, --help
          显示帮助


参数:
  <map_id>    map 或 multimap 的标识符。
  <key>       要插入或更新的 key。
  <value>...  一个或多个要关联到该 key 的值。

说明:
  - 普通 map 每个 key 只允许一个 value。
  - multimap 支持同一 key 关联多个 value。
  - 在添加数据前，请先使用 `map-create` 创建集合。

示例:
  map-add session_map session123 user1
  map-add multi_ip_map 192.168.0.1 login blocked
```

### `map-create`
```
按给定 ID 和作用域创建 map 或 multimap 集合。

用法: map-create [OPTIONS] <map_id>

参数:
  <map_id>
          要创建的 map/multimap 的 ID

选项:
  -m, --multi
          创建 multimap

      --global
          使用全局作用域
          
          [aliases: --export]

      --chain
          使用链级作用域（默认）

      --block
          使用块级作用域
          
          [aliases: --local]

  -h, --help
          显示帮助


选项:
  -multi                创建 multimap（一个 key 可对应多个 value）。
  -global, -export      全局作用域。
  -chain                process chain 作用域（默认）。
  -block, -local        块级本地作用域。

说明:
  - 如果未指定作用域，则默认使用 chain 级作用域。
  - 使用 `-multi` 可以创建 multimap，而不是普通 map。

示例:
  map-create trusted_hosts
  map-create -global user_token_map
  map-create -multi -local ip_event_map
```

### `map-remove`
```
从 map 或 multimap 集合中删除 key 或 key-value 对。

用法: map-remove <map_id> <key> [values]...

参数:
  <map_id>
          map 或 multimap 的 ID

  <key>
          要删除或更新的 key

  [values]...
          可选：在该 key 下要删除的 value

选项:
  -h, --help
          显示帮助


用法:
  map-remove <map_id> <key>
  map-remove <map_id> <key> <value>...
  
参数:
  <map_id>    map 或 multimap 的 ID。
  <key>       要删除或修改的 key。
  <value>...  可选；一个或多个要删除的 value。

行为:
  - 如果只提供 key，则删除整个条目。
  - 如果同时提供 value：
      - 对 map 来说，只允许一个 value。
      - 对 multimap 来说，会删除该 key 下给出的 value 项。

示例:
  map-remove session_map session123
  map-remove multi_map 127.0.0.1 login_failed blocked
```

### `match-include`
```
匹配集合中的 key 或 key-value 项。

用法: match-include <collection> <key> [value]...

参数:
  <collection>
          目标集合变量名或集合 ID

  <key>
          要在集合中匹配的 key

  [value]...
          一个或多个要与 key 匹配的值

选项:
  -h, --help
          显示帮助


在目标集合中检查某个 key 或 key-value 是否存在。
此命令支持 set、map 和 multi-map 集合类型。

行为:
    - match-include <collection> <key>
    如果 <key> 存在于 set、map 或 multi-map 中，则匹配成功。

    - match-include <collection> <key> <value>
    如果 map 或 multi-map 中存在精确的 (key, value) 对，则匹配成功。

    - match-include <collection> <key> <value1> <value2> ...
    对 multi-map 来说，只有所有给定的 (key, valueN) 都存在时才成功。

说明:
  - 如果目标集合不存在，则匹配失败。
  - 仅支持精确匹配，不支持 glob 或 regex 模式。
  - 多个 value 必须分别写成独立参数，不能作为单个 list 传入。

示例:
    match-include $test.coll "test_value"
    match-include $HOST $REQ_host "www.test.com" && drop
    match-include $IP $REQ_ip "127.0.0.1" "192.168.100.1" && accept
```

### `set-add`
```
向 set 集合中添加一个或多个值。

用法: set-add <set_id> <value>...

参数:
  <set_id>
          目标 set 的 ID

  <value>...
          一个或多个要加入 set 的值

选项:
  -h, --help
          显示帮助


参数:
  <set_id>    目标 set 的标识符。
  <value>...  一个或多个要插入到 set 中的值。

说明:
  - 如果 set 不存在，则操作失败。
  - set 只存储唯一值。
  - 使用该命令前，先通过 `set-create` 初始化 set。

示例:
  set-add trusted_hosts "192.168.1.1" "192.168.100.1"
  set-add temp_set "flag_enabled"
```

### `set-create`
```
按给定标识符与作用域创建新的 set 集合。

用法: set-create [OPTIONS] <set_id>

参数:
  <set_id>
          要创建的 set 的 ID

选项:
      --global
          使用全局作用域
          
          [aliases: --export]

      --chain
          使用链级作用域（默认）

      --block
          使用块级作用域
          
          [aliases: --local]

  -h, --help
          显示帮助


参数:
  <set_id>    要创建的 set 集合标识符。

作用域选项:
  -global, -export    在全局作用域创建 set。
  -chain              在当前 process chain 作用域创建 set（默认）。
  -block, -local      在当前执行块（local）作用域创建 set。

说明:
  - 如果未指定作用域，则默认使用 chain 级作用域。
  - set 是由唯一字符串项组成的集合。
  - 后续可用 match-include 查询，或用 set-add/set-remove 修改。

示例:
  set-create -global trusted_hosts
  set-create -export trusted_hosts
  set-create session_flags
  set-create -block temp_set
  set-create -local temp_set
```

### `set-remove`
```
从 set 集合中删除值。

用法: set-remove <set_id> <value>...

参数:
  <set_id>
          要从中删除值的 set 的 ID

  <value>...
          一个或多个要从 set 中删除的值

选项:
  -h, --help
          显示帮助


参数:
  <set_id>    目标 set 的标识符。
  <value>...  一个或多个要从 set 中删除的值。

说明:
  - 如果 set 不存在，则操作失败。
  - 如果值不在 set 中，则忽略该项。
  - set 只存储唯一值。

示例:
  set-remove trusted_hosts "192.168.1.1"
  set-remove temp_set "flag_enabled"
```

## match 匹配

### `eq`
```
比较两个值是否相等（默认使用严格 typed 比较）。

用法: eq [OPTIONS] <value1> <value2>

参数:
  <value1>
          要比较的第一个值

  <value2>
          要比较的第二个值

选项:
  -i, --ignore-case
          启用大小写不敏感比较（仅 string-string）

  -l, --loose
          启用 string/number 宽松比较

  -h, --help
          显示帮助


比较两个值是否相等。

参数:
  <value1>        第一个待比较值
  <value2>        第二个待比较值

选项:
  --ignore-case   执行大小写不敏感比较（仅 string-string）
  --loose         启用 string/number 宽松比较

默认情况下，`eq` 使用严格 typed 比较：
  - 相同类型的标量值直接比较
  - 不同类型默认不相等，例如 Number(1) != String("1")

语法糖:
  - value1 == value2   => eq --loose value1 value2
  - value1 === value2  => eq value1 value2
  - 主要用于 if/elif 条件中提升可读性。

示例:
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
比较两个值是否不相等（默认使用严格 typed 比较）。

用法: ne [OPTIONS] <value1> <value2>

选项:
  -i, --ignore-case   大小写不敏感比较，仅用于 string-string
  -l, --loose         启用 string/number 宽松比较

语法糖:
  - value1 != value2   => ne --loose value1 value2
  - value1 !== value2  => ne value1 value2
  - 主要用于 if/elif 条件中提升可读性。

示例:
  ne 1 "1"                 # true under strict mode
  ne --loose 1 "1"         # false under loose mode
  ne --ignore-case "A" "a" # false
  if $REQ.port != "443" then ...
  if $REQ.role !== "admin" then ...
```

### `gt` / `ge` / `lt` / `le`
```
数值比较命令。

用法:
  gt [OPTIONS] <value1> <value2>   # value1 > value2
  ge [OPTIONS] <value1> <value2>   # value1 >= value2
  lt [OPTIONS] <value1> <value2>   # value1 < value2
  le [OPTIONS] <value1> <value2>   # value1 <= value2

选项:
  -l, --loose    启用 string/number 宽松数值解析

行为:
  - 严格模式下，仅 Number 值可比较。
  - 宽松模式下，如果字符串可解析为数值，则允许 String/Number 混合比较。
  - 不可比较的值返回 false。

语法糖（严格模式）:
  - value1 > value2   => gt value1 value2
  - value1 >= value2  => ge value1 value2
  - value1 < value2   => lt value1 value2
  - value1 <= value2  => le value1 value2
  - 如果需要宽松数值解析，请显式使用：gt/ge/lt/le --loose ...

示例:
  gt 10 9
  ge --loose "2" 2
  lt --loose "1.5" 2
  if $REQ.port >= 443 then ...
  if $latency_ms < 100 then ...
```

### `match`
```
使用 glob 模式匹配一个值。

用法: match [OPTIONS] <value> <pattern>

参数:
  <value>
          要匹配的输入字符串或变量

  <pattern>
          要匹配的 glob 模式

选项:
      --no-ignore-case
          执行大小写敏感匹配（默认大小写不敏感）

  -h, --help
          显示帮助


参数:
  <value>     要匹配的字符串或变量。
  <pattern>   glob 模式，例如 *.domain.com、home.*.site.org

选项:
  --no-ignore-case   执行大小写敏感匹配（默认大小写不敏感）

行为:
  - 使用 shell 风格的 glob 匹配。
  - 默认大小写不敏感。
  - pattern 需要符合 shell glob 语法：
      *  — 匹配任意长度字符
      ?  — 匹配单个字符
      [...] — 字符类

示例:
  match $REQ_HEADER.host "*.local"
  match username "admin*"
```

### `match-reg`
```
使用正则表达式匹配一个值，支持可选的命名捕获。

用法: match-reg [OPTIONS] <value> <pattern>

参数:
  <value>
          要匹配的输入字符串或变量

  <pattern>
          正则表达式模式

选项:
      --no-ignore-case
          执行大小写敏感匹配（默认大小写不敏感）

      --capture <name>
          保存正则捕获到环境变量时使用的名称

  -h, --help
          显示帮助


参数:
  <value>      要匹配的字符串。
  <pattern>    要使用的正则表达式。

选项:
  --capture name   将捕获组写入环境变量，例如 name[0]、name[1] ...
  --no-ignore-case   执行大小写敏感匹配（默认大小写不敏感）

行为:
  - 使用 Rust 风格正则表达式。
  - 如果模式匹配成功，则返回 success；否则返回 error。
  - 如果提供 `--capture`，则捕获组会写入环境变量：
      name[0] 表示第一个捕获组，
      name[1] 表示第二个捕获组，以此类推。
  - 默认行为为大小写不敏感匹配。

示例:
  match-reg $REQ_HEADER.host "^(.*)\.local$"
  match-reg --capture parts $REQ_HEADER.host "^(.+)\.(local|dev)$"
```

### `range`
```
检查某个变量值是否位于数值范围内。

用法: range <value> <begin> <end>

参数:
  <value>
          要测试的变量或值

  <begin>
          范围起点（含）

  <end>
          范围终点（含）

选项:
  -h, --help
          显示帮助


参数:
  <value>     要测试的变量或值
  <begin>     包含的下界。
  <end>       包含的上界。

行为:
  - 所有值都会自动按整数或浮点数解析。
  - 支持混合类型比较，例如 int + float，会统一转为 float。
  - 如果 value ∈ [begin, end]，则返回 true。

示例:
  range 5 1 10
  range 3.14 0.0 3.15
  range $REQ.port 1000 2000
```

## control 控制流

### `accept`
```
执行会终止当前 process chain 执行的控制动作。

用法: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

选项:
  -h, --help
          显示帮助


可用动作:
  drop      等价于 `exit drop`，并以结果 `drop` 终止。
  accept    等价于 `exit accept`，并以结果 `accept` 终止。
  reject    等价于 `exit reject`，并以结果 `reject` 终止。

说明:
  - 所有动作都会立刻停止整个 process chain 列表执行。
  - 返回值会传递给外层调用方，例如 dispatcher 或协议栈。
  - 这些动作通常配合 `match`、`eq`、`range` 等条件表达式使用。

示例:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `break`
```
中断当前结构化循环，可选附带一个值。

用法: break [value]

参数:
  [value]
          可选的 break 值

选项:
  -h, --help
          显示帮助


用法:
  break           不带值地跳出。
  break <value>   带指定值跳出。

行为:
  - 立即结束当前循环的执行。
  - 只影响当前所在的循环层级。
  - 如果提供返回值，则会传递给上层执行环境。

示例:
  break;
  break "map failed"
```

### `drop`
```
执行会终止当前 process chain 执行的控制动作。

用法: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

选项:
  -h, --help
          显示帮助


可用动作:
  drop      等价于 `exit drop`，并以结果 `drop` 终止。
  accept    等价于 `exit accept`，并以结果 `accept` 终止。
  reject    等价于 `exit reject`，并以结果 `reject` 终止。

说明:
  - 所有动作都会立即停止整个 process chain 列表。
  - 返回值会传递给外层调用方，例如 dispatcher 或协议栈。
  - 这些动作通常配合 `match`、`eq`、`range` 等条件表达式使用。

示例:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `error`
```
以错误状态从当前作用域返回，可选附带一个值。

用法: error [OPTIONS] [value]

参数:
  [value]
      可选的错误值

选项:
      --from <LEVEL>
          指定要退出的执行层级。
          
          [默认: block]
          [possible values: block, chain, lib]

  -h, --help
          显示帮助


说明:
  以 error 状态结束指定层级的执行，并可附带错误消息。
  这是控制 exec/return 流程的主要错误返回机制。

作用域层级（--from）:
  block（默认）: 只退出当前 block。执行会继续进入 process-chain 中的下一个 block。

  chain: 退出整个当前 process-chain。如果该 chain 是通过 `exec --chain` 调用的，
         则控制权和返回值会交还给调用方；如果是通过 `exec --lib` 进入的，
         则会返回到 library 中的下一条 chain。

  lib:   退出整个当前 library，无论当前嵌套多深。
         如果该 library 是通过 `exec --lib` 调用的，则控制权返回给该调用方。
         这对于处理复杂嵌套库调用中的提前失败非常重要。

示例:
  # 让当前 block 以错误结束，不附带消息（默认作用域）
  error

  # 让当前 block 以指定错误消息结束
  error "invalid input provided"

  # 因缺少必需资源而让整个 process-chain 失败
  error --from chain "permission denied to access file"

  # library 深层 block 提前终止整个库执行
  error --from lib "not found"
```

### `exec`
```
按标识符执行 block、process-chain 或 library。

用法: exec <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>|BLOCK_ID>

参数:
  [BLOCK_ID]
          默认从当前 chain 中执行一个 block。

选项:
      --block <BLOCK_ID>
      按 ID 执行 block。

      --chain <CHAIN_ID>
      按 ID 执行 process-chain。

      --lib <LIB_ID>
      按 ID 执行 library。

  -h, --help
          显示帮助


说明:
  调用一个可复用执行单元（block、chain 或 lib），并等待其执行完成后再继续。
  目标执行单元会根据其 ID 和当前上下文进行解析。

标识符解析规则:
  ID 的格式决定目标单元的搜索范围。

  对 `--block <ID>`:
    - `lib:chain:block`:  完全限定名。先全局查找 library，再查 chain，最后查 block。
    - `chain:block`:      部分限定名。先在 *当前 library* 中查找 chain，再做全局查找。
    - `block`:            本地名。仅在 *当前 process-chain* 内查找 block。

  对 `--chain <ID>`:
    - `lib:chain`:        完全限定名。先全局查找 library，再查找 chain。
    - `chain`:            本地名。先在 *当前 library* 内查找，再做全局查找。

  对 `--lib <ID>`:
    - `lib`:              全局名。直接在全局范围查找 library。

EXAMPLES:
  # 执行当前 process-chain 内的一个 block
  exec --block verify_token

  # 执行特定 chain 中的 block（优先在当前 lib 中查找）
  exec --block auth_flow:get_user_info

  # 使用完全限定的全局 ID 执行 block
  exec --block security_lib:sso_flow:validate_jwt

  # 执行一个 chain（优先在当前 lib 中查找）
  exec --chain user_login_flow

  # 执行一个全局唯一的 library
  exec --lib common_utils
```

### `invoke`
```
用命名参数调用 block、process-chain 或 library。

用法: invoke [OPTIONS] <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>|BLOCK_ID>

参数:
  [BLOCK_ID]
          默认调用当前 chain 中的一个 block。

选项:
      --block <BLOCK_ID>
      按 ID 调用 block。

      --chain <CHAIN_ID>
          按 ID 调用 process-chain。

      --lib <LIB_ID>
          按 ID 调用 library。

      --arg <KEY> <VALUE>
          传给被调方的命名参数，可重复出现。

  -h, --help
          显示帮助


说明:
  `invoke` 与 `exec` 类似，但会通过 `$__args.<key>` 向被调方传递命名参数。

参数传递:
  - `--arg <key> <value>` 可以重复出现。
  - `<value>` 可以是字面量、变量、命令替换或集合引用。
  - 被调方通过 `$__args.<key>` 读取参数。

EXAMPLES:
  invoke --chain auth_flow --arg user $REQ.user --arg pass $REQ.pass
  invoke --block helper_block --arg req $REQ
```

### `goto`
```
尾转移到指定的 block/chain/lib，并从选定作用域返回。

用法: goto [OPTIONS] <--block <BLOCK_ID>|--chain <CHAIN_ID>|--lib <LIB_ID>>

选项:
      --block <BLOCK_ID>
      转移到指定 ID 的 block。

      --chain <CHAIN_ID>
          转移到指定 ID 的 process-chain。

      --lib <LIB_ID>
          转移到指定 ID 的 library。

      --from <LEVEL>
          目标执行完成后的默认 return/error 作用域。可选值：block|chain|lib。

      --ok-from <LEVEL>
          success 返回作用域覆盖项。可选值：block|chain|lib。

      --err-from <LEVEL>
          error 返回作用域覆盖项。可选值：block|chain|lib。

      --arg <KEY> <VALUE>
          传给目标的命名参数，可重复出现。

  -h, --help
          显示帮助


说明:
  `goto` 是一个结构化尾转移命令。它会先执行目标（语义与 `invoke` 相同），
  再把结果映射为从选定调用层级发出的 return/error。

目标 ID 格式:
  与 exec/invoke 相同：
  - --block: block | chain:block | lib:chain:block
  - --chain: chain | lib:chain
  - --lib: lib

返回层级:
  - `--from` 设定 success/error 的共同默认映射层级。
  - `--ok-from` 覆盖 success 的映射层级。
  - `--err-from` 覆盖 error 的映射层级。
  - 如果都省略，则默认使用 `block`，与不带 `--from` 的 `return`/`error` 一致。

结果映射:
  - target success(value) -> return --from <ok-level> value
  - target error(value)   -> error  --from <err-level> value

说明:
  - 这不是底层指令指针跳转。
  - 同一执行路径中，`goto` 之后的语句不会再执行。

EXAMPLES:
  goto --chain fallback_chain
  goto --chain auth_flow --from lib
  goto --chain auth_flow --from chain --err-from lib
  goto --chain auth_flow --ok-from lib --err-from chain
  goto --block helper --arg req $REQ
```

### `exit`
```
从当前 process chain 列表返回，可附带返回值。

用法: exit [value]

参数:
  [value]
      可选返回值

选项:
  -h, --help
          显示帮助


用法:
  exit           不带值退出。
  exit <value>   带指定字符串值退出。

行为:
  - 结束当前 process chain 列表的执行，并返回到最上层调用方。
  - 如果有返回值，会一并传递给调用方。

示例:
  exit
  exit accept
  exit "invalid input"
```

### `reject`
```
执行会终止当前 process chain 执行的控制动作。

用法: 
    [expression] && drop
    match $ip "192.168.0.*" && accept
    match $uid "blacklist" && reject

选项:
  -h, --help
          显示帮助


可用动作:
  drop      等价于 `exit drop`，并以结果 `drop` 终止。
  accept    等价于 `exit accept`，并以结果 `accept` 终止。
  reject    等价于 `exit reject`，并以结果 `reject` 终止。

说明:
  - 所有动作都会立即停止整个 process chain 列表。
  - 返回值会传递给外层调用方，例如 dispatcher 或协议栈。
  - 这些动作通常配合 `match`、`eq`、`range` 等条件表达式使用。

示例:
    match $user "admin" && accept
    match $ip "10.0.*.*" && drop
    range $port 1000 2000 && reject
```

### `return`
```
从当前调用者成功返回，可附带返回值。

用法: return [OPTIONS] [value]

参数:
  [value]
      可选返回值

选项:
      --from <LEVEL>
          指定要返回的执行层级。
          
          [默认: block]
          [possible values: block, chain, lib]

  -h, --help
          显示帮助


说明:
  在指定层级终止执行并将控制权返回给调用方，可选附带返回值。
  这是控制 exec/return 流程的主要成功返回机制。

作用域层级（--from）:
  block（默认）: 只退出当前 block。执行会继续进入 process-chain 的下一个 block。

  chain: 退出整个当前 process-chain。如果该 chain 是通过 `exec --chain` 调用的，
         则控制权和返回值会交还给调用方。

  lib:   退出整个当前 library，无论当前嵌套多深。
         如果该 library 是通过 `exec --lib` 调用的，则控制权返回给该调用方。
         这对于处理复杂嵌套库调用中的提前返回非常重要。

示例:
  # 从当前 block 返回，不附带值（默认作用域）
  return

  # 从当前 block 返回，并携带值 "done"
  return done

  # 通过 `exec --chain` 调用的 chain 将结果返回给调用方
  return --from chain "authentication successful"

  # library 深层 block 提前终止整个库执行
  return --from lib "FATAL: configuration missing"
```

## map-reduce 映射归约

### `map`
```
对集合执行 map-reduce 操作。

用法: 
    map --begin <init-cmd> --cmd <map-cmd> [--reduce <reduce-cmd>] <coll>
    map <coll> <map-cmd> reduce <reduce-cmd>
    map <coll> <map-cmd>

参数:
  [coll]
          集合名称（位置参数模式必填）

  [map_cmd]
      位置参数模式下的 map 命令（必填）

  [reduce_kw]
      位置参数模式下的关键字 `reduce`（可选）

  [reduce_cmd]
      位置参数模式下的 reduce 命令（使用 `reduce` 时必填）

选项:
      --begin <begin>
          处理开始前执行一次的命令（仅长参数模式，可选）

      --map <map>
          对每个元素执行的 map 命令（长参数模式必填）

      --reduce <reduce>
          用于聚合结果的 reduce 命令（仅长参数模式，可选）

  -h, --help
          显示帮助


选项:
长参数模式选项:
  --begin <init-cmd>    在处理前执行一次的初始化命令（仅长参数模式）
  --cmd <map-cmd>       对每个元素执行的 map 命令（长参数模式必填）
  --reduce <reduce-cmd> 聚合结果的 reduce 命令（长参数模式可选）
    -h, --help            显示帮助
  <coll>                集合名称（两种模式都必填）

位置参数模式参数:
  <coll>                集合名称（两种模式都必填）
  <map_cmd>             map 命令（位置参数模式必填）
  <reduce_kw>           关键字 `reduce`（位置参数模式可选）
  <reduce_cmd>          reduce 命令（使用 `reduce` 时必填）

示例:
  长参数模式:
    map --begin $(local sum = "") --map $($sum = append ${key} sum') --reduce $(echo ${sum}) my_coll
  位置参数模式:
    map my_coll $($sum = append ${key} sum') reduce $(echo ${sum})
```

## External Commands 外部命令

### `http-probe`
```
探测传入 HTTP 流，提取 method、path、version 和 host。

用法: http-probe

选项:
  -h, --help
          显示帮助


尝试从传入的明文 HTTP 流中提取请求行和关键头部信息。

用法:
  http-probe

行为:
  - 该命令会读取传入流的起始内容，判断其中是否包含有效的 HTTP 请求。
  - 如果请求有效，会提取以下信息并写回环境：
      $REQ.dest_host        ← `Host:` 头中的主机名
      $REQ.app_protocol     ← "http"
      $REQ.ext.method       ← HTTP 方法，例如 GET、POST
      $REQ.ext.path         ← 请求路径，例如 /index.html
      $REQ.ext.version      ← HTTP 版本字符串，例如 HTTP/1.1
      $REQ.ext.url          ← 基于 host 和 path 拼出的完整 URL
  - 如果解析成功并找到 host，则返回 success(host)。
  - 如果请求无效，或缺少 Host 头（HTTP/1.1 必需），则返回 error。

前置要求:
  - 环境中必须存在变量 $REQ.incoming_stream。
    其类型必须为 AsyncStream。

示例:
  http-probe && match $REQ.dest_host "api.example.com" && accept
  http-probe && match $REQ.ext.path "/admin/*" && drop
```

### `https-sni-probe`
```
探测 TLS Client Hello 中的 SNI

用法: https-sni-probe

选项:
  -h, --help
          显示帮助


尝试从传入 TLS 流中探测 SNI（Server Name Indication）。

用法:
  https-sni-probe

行为:
  - 该命令会检查传入流的起始内容，判断其是否为有效的 HTTPS 连接。
  - 如果连接是 HTTPS 且包含有效的 SNI 字段，则会提取主机名并更新环境：
      $REQ.dest_host     ← 提取到的主机名
      $REQ.app_protocol  ← "https"
  - 如果成功解析出 SNI 主机名，则返回 success(host)。
  - 如果连接不是 HTTPS，或没有找到 SNI，则返回 error。

前置要求:
  - 环境中必须存在变量 $REQ.incoming_stream。
    其类型必须为 AsyncStream。

示例:
  https-sni-probe && accept
```

## statements 结构化语句

### 结构化语句总览
```
这些是 DSL 语法级结构，不是独立命令。它们在 statement 层解析，因此不会出现在命令注册表中。
```

### `if` / `elif` / `else` / `end`
```
根据布尔条件或谓词条件分支。

语法:
  if <condition> then
      ...
  elif <condition> then
      ...
  else
      ...
  end

支持的条件形式:
  - 谓词命令:
      if eq $REQ.role "admin" then
  - 取反谓词命令:
      if !eq $REQ.protocol "https" then
  - 中缀比较语法糖:
      if $one == "1" then
      if $one === "1" then
      if $one != "1" then
      if $one !== "1" then
      if $one > 0 then
      if $one >= 1 then
      if $one < 2 then
      if $one <= 1 then

说明:
  - `==` / `!=` 使用宽松比较语义。
  - `===` / `!==` 使用严格 typed 比较语义。
  - 缺少 `end` 会在 parse/link 阶段报错。
```

### `for ... in ... then ... end`
```
使用结构化循环语义遍历集合。

语法:
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

行为:
  - 循环变量只在 for-block 内可见。
  - 与外层重名的变量会在循环结束后恢复。
  - `break [value]` 只退出当前循环。
  - `return` / `error` / `exit` / `goto` 会继续按既有语义向外传播。

遍历安全性:
  - 遍历过程中修改同一个集合会被拒绝。
  - 这一约束适用于 list/set/map/multi-map 遍历。

示例:
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
执行一次命令替换，再按 CommandResult 类型分支。

语法:
  match-result $(<command>)
  ok(value)
      ...
  err(err_value)
      ...
  control(action, from, value)
      ...
  end

规则:
  - 输入必须是单个命令替换：`$(...)`。
  - `ok(...)` 处理 Success(value)。
  - `err(...)` 处理 Error(value)。
  - `control(action, from, value)` 处理 Control 结果。
  - 未处理的结果类型会原样继续向外传播。

示例:
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
