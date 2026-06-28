# BNS device mini map 内嵌 zone-config 对称化 + 解析优先级修正 TODO

> **设计意图(架构者确认)**：zone-config 里**本来就该内嵌一个 device 的 mini map 字段**,
> 与内嵌 `boot_jwt` **完全对称**。`device_mini_doc` 和 `boot` 拆成独立 doc_type 的**根本原因都是
> DNS TXT 256 字节塞不下**,才被迫单独拆出去。即:内嵌于 zone-config 是规范形态,独立 doc 是 DNS 妥协。
>
> 参见 zone/boot 原子化设计、`BNS 智能合约接口设计.md` §5.3、SN-BNS-Contoller.md。

---

## 代码现状(已 review,2026-06-27)

对称性在代码里是**断的**——boot 内嵌路径接通了,device 内嵌路径完全没接:

| 维度 | boot(已接通) | device(未接通) |
| --- | --- | --- |
| 从 zone-config 抽取 | `ZoneDocument.boot_jwt = find_boot_jwt(zone_raw)`([sn_resolver.rs:297](../../src/components/cyfs-sn/src/sn_resolver.rs:297) / 2190) | **无** —— `ZoneDocument`(line 270)无 devices 字段,只抽了 `gateway_device_name` 指针 |
| 解析时读内嵌 | `resolve_*` 会用 `boot_doc.raw` / legacy boot_jwt fallback | **`resolve_device_mini_doc` 从不读 `zone_doc.raw`** |
| 独立 doc 来源 | 独立 `boot` 文档 | zone 级聚合 `device_mini_doc` + child 名 `{device}.{zone}`(doc_type ∈ `["device_mini_doc","doc"]`) |

`resolve_device_mini_doc`([sn_resolver.rs:1308](../../src/components/cyfs-sn/src/sn_resolver.rs:1308))当前来源顺序:
① zone 级**独立聚合**文档 `get_document(zone_name,"device_mini_doc")` 取 `devices[name]`(line 1313–1321)→
② child 名独立文档(line 1323–1335)→ ③ legacy(line 1337–1349)。
`devices` map 只在独立聚合文档上读(line 2272、2331),**从不读 zone-config 内嵌**。

已确认要点:
- ✅ 标准 `"doc"` 类型就能作为设备文档来源(line 1324),与"mini_doc 也是标准 doc"一致。
- ❌ **zone-config 内嵌 device map 路径未实现、未覆盖** —— 因历史只走 DNS 拆分路径,这条触不到。
- ❌ **优先级与意图相反** —— 当前聚合优先;意图是"用户手工独立发布的 device doc 以独立为准"。

---

## 待办项

### 1. 接通 device 内嵌路径,与 boot 对称(核心)
- [ ] `ZoneDocument` 增加内嵌 device mini map 字段,从 `zone_raw` 抽取(对称 `find_boot_jwt` → 新增 `find_devices`/`find_device_mini_map`)。
- [ ] `resolve_device_mini_doc` 增加"从 zone-config 内嵌 devices map 解析"这一来源,与 boot 的内嵌 fallback 对称。
- [ ] 明确内嵌(规范)与独立 `device_mini_doc`(DNS 妥协)语义一致:解析同一设备,两条路径结果应等价。

### 2. 厘清并修正解析优先级
- [ ] 定夺优先级。四个来源:A=child 名独立文档(用户手工发布) / B=zone 级独立聚合 device_mini_doc / C=zone-config 内嵌 devices map / D=legacy。
      B 与 C 是"同一份聚合 map 的两种存储"(C 内嵌=规范,B 拆出=DNS 妥协)。
- [ ] 意图:**A(独立 per-device override)优先**,其后才是聚合(B/C,取存在者),最后 D。
      当前实现是聚合优先,需把 child 名独立文档提到聚合之前。

### 3. 补测试(当前最大缺口)
- [ ] **内嵌路径**:zone-config 内嵌 device map 时,`resolve_device_mini_doc` 能解析出设备(目前零覆盖)。
- [ ] **内嵌/独立一致性**:同一设备,zone-config 内嵌 vs 独立 `device_mini_doc` 解析结果等价(对标 boot 内嵌 fallback 一致性测试)。
- [ ] **独立优先**:同设备同时存在聚合条目 + child 名独立 `doc` 时,断言返回独立发布的那份。
- [ ] **标准 doc 来源**:`doc_type="doc"` 在 child 名发布设备文档能被解析。
- [ ] **正向闭环**:SN controller 合法 authority publish→resolve `device_mini_doc`(目前只有负向被拒断言 `sn_controller_cannot_publish_owner_scoped_device_doc`)。
- [ ] 同理给 `relay_assignment` 补正向 publish→resolve(也只有负向测试)。

### 4. 关联清理
- [ ] 检查 SN-BNS-Contoller / sn_bns_controller.rs / sn_resolver.rs 注释命名,统一表述为"内嵌 zone-config 为规范、独立 doc 为 DNS 妥协"。

---

## 验收
- zone-config 内嵌 device map 能被 resolver 解析,且与独立 `device_mini_doc` 结果等价(有测试)。
- 同一 device 同时有聚合条目与 child 名独立文档时,resolver 返回**独立发布**的那份。
- `device_mini_doc` 与 `relay_assignment` 均有正向 publish→resolve 用例。
