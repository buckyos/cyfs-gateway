# JSON 与 MapCollection 转换工具

## 概述

为了简化 JSON 与 `MapCollectionRef` 之间的转换，我们创建了 `json_collection` 模块，提供了高性能的 trait 实现和便捷的工具函数。

## 核心组件

### 1. JsonMapCollection Trait

为 `MapCollectionRef` 实现的 trait，提供了与 JSON 的双向转换能力。

```rust
use cyfs_gateway_lib::{JsonMapCollection, MapCollectionRef};

// 从 JSON 创建 MapCollection
let json = serde_json::json!({
    "name": "Alice",
    "age": 30,
    "enabled": true
});
let map = MapCollectionRef::from_json(&json).await?;

// 将 MapCollection 转换为 JSON
let json_back = map.to_json().await?;
```

### 2. 工具函数

#### `json_value_to_collection_value`

将 `serde_json::Value` 转换为 `CollectionValue`。

```rust
use cyfs_gateway_lib::json_value_to_collection_value;

let json_value = serde_json::json!(42);
let coll_value = json_value_to_collection_value(&json_value);
```

#### `collection_value_to_json_value`

将 `CollectionValue` 转换为 `serde_json::Value`，支持智能类型识别。

```rust
use cyfs_gateway_lib::collection_value_to_json_value;
use cyfs_process_chain::CollectionValue;

let coll_value = CollectionValue::String("42".to_string());
let json_value = collection_value_to_json_value(&coll_value);
// 结果: JSON Number(42)
```

### 3. 简化版本

如果不需要智能类型转换，可以使用简化版本：

```rust
use cyfs_gateway_lib::{json_to_map_simple, map_to_json_simple};

// 所有值都保持为字符串
let map = json_to_map_simple(&json).await?;
let json = map_to_json_simple(&map).await?;
```

## 类型转换规则

### JSON → CollectionValue

| JSON 类型 | CollectionValue |
|-----------|-----------------|
| String    | String          |
| Number    | String (保留精度) |
| Boolean   | String ("true"/"false") |
| Null      | String ("null") |
| Object/Array | String (JSON 表示) |

### CollectionValue → JSON (智能转换)

| CollectionValue 内容 | JSON 类型 | 示例 |
|---------------------|-----------|------|
| 整数字符串 | Number | "42" → 42 |
| 浮点数字符串 | Number | "3.14" → 3.14 |
| 布尔字符串 | Boolean | "true" → true |
| JSON 字符串 | Object/Array | "{...}" → {...} |
| 其他 | String | "hello" → "hello" |

## 性能优势

### 1. Trait 实现

通过为 `MapCollectionRef` 直接实现 trait，避免了中间转换步骤：

```rust
// 优化前（手动转换）
let map_dump = req_map.dump().await?;
let mut json_obj = serde_json::Map::new();
for (key, value) in map_dump {
    let json_value = match value {
        CollectionValue::String(s) => {
            if let Ok(n) = s.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else {
                serde_json::Value::String(s)
            }
        }
        _ => serde_json::Value::String(value.to_string()),
    };
    json_obj.insert(key, json_value);
}

// 优化后（使用 trait）
let json = req_map.to_json().await?;
```

### 2. 零拷贝优化

在可能的情况下，转换过程避免不必要的内存分配和复制。

### 3. 延迟计算

类型识别（字符串→数字/布尔值）仅在需要时进行。

## cmd_qa 使用示例

`cmd_qa` 命令现在使用新的转换工具：

```rust
// 将请求 map 转换为 JSON
let request_json = req_map.to_json().await?;

// 调用 QA server
let response_json = qa_server.serve_question(&request_json).await?;

// 将响应 JSON 转换为 map
let answer_map = MapCollectionRef::from_json(&response_json).await?;

// 存储到环境变量
context.env().create("ANSWER", CollectionValue::Map(answer_map), EnvLevel::Chain).await?;
```

## 在 Process Chain 中使用

```yaml
# process_chain.yaml
chains:
  - id: qa_example
    commands:
      # 准备请求数据
      - map_create REQUEST
      - map_set REQUEST question "What is Rust?"
      - map_set REQUEST context "programming language"
      
      # 调用 QA server
      - qa my_qa_server REQUEST
      
      # 使用响应数据
      - log "Answer: $ANSWER.answer"
      - log "Confidence: $ANSWER.confidence"
```

## 错误处理

```rust
use cyfs_gateway_lib::JsonCollectionError;

match MapCollectionRef::from_json(&json).await {
    Ok(map) => {
        // 成功处理
    }
    Err(JsonCollectionError::NotObject) => {
        // JSON 不是对象类型
    }
    Err(JsonCollectionError::InsertFailed(e)) => {
        // 插入 map 失败
    }
    Err(JsonCollectionError::DumpFailed(e)) => {
        // 导出 map 失败
    }
}
```

## 测试

模块包含完整的单元测试：

```bash
cd src
cargo test --package cyfs-gateway-lib json_collection
```

## 扩展性

如果需要自定义转换逻辑，可以：

1. 实现自己的转换函数
2. 创建新的 wrapper 类型并实现相应的 trait
3. 使用 `collection_value_to_json_value` 和 `json_value_to_collection_value` 作为基础

## 未来优化方向

1. **批量转换优化**：对于大型 map，可以实现并行转换
2. **自定义类型映射**：允许用户定义特殊类型的转换规则
3. **序列化缓存**：对于频繁转换的 map，可以缓存 JSON 表示
4. **流式转换**：支持超大 JSON 对象的流式处理

## 参考

- 源码：`src/components/cyfs-gateway-lib/src/json_collection.rs`
- 使用示例：`src/components/cyfs-gateway-lib/src/server/cmd_qa.rs`
- 测试：`src/components/cyfs-gateway-lib/src/json_collection.rs` (tests 模块)

