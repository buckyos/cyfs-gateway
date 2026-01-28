# Control Panel API
应该与CLI的设计保持有一定的理念相同性

## 对象树管理API
- list对象
- 根据对象id查询对象的状态

## 数据库API
- 基本是CRUD
- 可以针对多个库Query合并

## 配置文件管理 API
- 获得config tree
- 同步
- 要求reload config
- 修改特定的config 根本上是json_path API，可以原子的修改一个config,而不是使用 download/upload模式来修改某个配置文件（这里也可以做权限管理）
- 需要一个复制的本地tslib,来解析各种格式(这个是buckyos-sdk的一部分?)

## 执行特定命令
比如查询Host-Tag库这种，都是构造一个命令"query_db" 命令执行得到结果



