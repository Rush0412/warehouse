# Correlation Aggregation Capabilities

本文档汇总服务当前对四类 Sigma 关联规则（`event_count`、`value_count`、`temporal`、`temporal_ordered`）的解析与转化逻辑，便于模型推理或人工查阅。

## 处理流程概览

1. **解析阶段（`app/services/parser.py`）**
   - 对 `tags`、`metadata` 做预清洗，消除非法命名空间并补齐 `metadata.custom_tags`。
   - 为 `ordered_temporal`、`temporal_unordered` 等别名映射到 pysigma 支持的枚举值。
   - 将 `condition: all/any/one` 归一化为 `{ gte: … }` 字典；若缺省则使用默认阈值。
   - 在缺失时，基于 `metadata` 自动回填 `correlation.timespan`、`group-by`、`condition` 等字段。

2. **转换阶段（`app/services/converter.py`）**
   - 首先输出基础规则的查询字符串（Aviator / Flink SQL / Flink CEP）。
   - `_collect_reference_queries` 会将同一文档中的其它基础规则全部转为目标格式，供聚合使用。
   - `AggregationQueryBuilder` 读取基础查询、关联规则与 `metadata`，生成 `AggregationResult`（窗口、分组、阈值、聚合查询、提示信息）。

3. **结果返回**
   - `ConversionResult` 同时携带基础查询和聚合附加信息，便于调用方直接使用或串联。

## 通用解析与默认值

| 项目 | 默认/行为 |
| ---- | -------- |
| `aggregation_timespan` | 优先使用 `metadata.aggregation_timespan`；其次读取 `correlation.timespan`; 未提供时默认 `5m` |
| `aggregation_threshold` | 优先使用 `correlation.condition`; 其次使用 `metadata.aggregation_threshold`; 默认 `1` |
| `group-by` | 优先使用 `correlation.group-by`; 否则从 `metadata.dimensions` 补齐；缺省时给出提示 |
| `aggregation_event_time_field` | 默认 `event_time`，可由 `metadata.aggregation_event_time_field` 覆盖 |
| `aggregation_pattern_alias` | 用于 CEP/有序模式别名；未提供时在 CEP 中回退到自动生成的别名 |
| 关联阈值与比较符 | 支持 `gte`/`gt`/`eq`/`lt`/`lte`，分别映射到 `>=`/`>`/`=`/`<`/`<=`；若出现未知操作符，会在结果中提示并回退到 `>=` |
| 关联阈值校正 | `temporal` / `temporal_ordered` 若阈值小于规则数量，会提升到规则数并记录提示；有序/无序时仅支持 `>=` 与 `=` 两种语义 |

## 类型能力说明

### event_count

- **逻辑**：时间窗口内统计某基础规则匹配的事件数量，阈值由 `condition.gte` 或 `metadata` 控制。
- **比较符**：支持 `>=`、`>`、`=`、`<`、`<=`，会直接映射到 `HAVING COUNT(*)` 或等价语句。
- **Flink SQL**：使用 `TUMBLE` 窗口，`COUNT(*)`，并输出 `window_start/window_end` 字段。
- **Aviator**：生成 `WINDOW … BY … HAVING COUNT >= n`，`FILTER` 子句沿用基础查询。
- **Flink CEP**：构建 `PATTERN SEQ(alias+)`，`GROUP BY` 与 `HAVING COUNT(alias)`。

### value_count

- **逻辑**：对指定字段取去重计数。需要在关联规则的 `condition.field` 或 `metadata.aggregation_field` 中提供字段名。
- **比较符**：同上，使用 `COUNT(DISTINCT …)` 组合。
- **Flink SQL**：`COUNT(DISTINCT <field>) AS distinct_value_count`，窗口与分组与 `event_count` 相同。
- **Aviator**：`HAVING COUNT_DISTINCT(field) >= n`。
- **Flink CEP**：`HAVING COUNT(DISTINCT alias.field) >= n`。若缺少字段引用，则不会输出聚合查询。

### temporal（时间共存）

- **逻辑**：多个基础规则在窗口内共同命中，不关注顺序。
- **比较符**：仅支持 `>=` 与 `=`，其它比较符会在结果中提示并回退为 `>=`。
- **Flink SQL**：
  - `filtered_events` CTE 将各规则按照 `rule_name` 区分后 `UNION ALL`。
  - `windowed_events` 按事件时间聚合，`COUNT(DISTINCT rule_name)`。
  - 阈值提升至规则数，确保所有规则均匹配。
- **Aviator**：生成 `MATCH CO_OCCURRENCE` 模式，每个规则对应一条 `RULE 'name' => (query)`。
- **Flink CEP**：同样输出顺序模式 `PATTERN SEQ(A, B, …)`，并提示“未显式保证顺序”。条件部分为每条规则的 WHERE 子句，并自动加别名。

### temporal_ordered（有序时间）

- **逻辑**：强调顺序的时间共存。
- **比较符**：同 `temporal`，仅支持 `>=` 与 `=`。
- **Flink SQL**：使用 `MATCH_RECOGNIZE` 模式；每个别名 `R1/R2/...` 对应一条规则，`FIRST()/LAST()` 测量时间。
- **Aviator**：`MATCH SEQUENCE`，每步 `STEP n 'name' => (query)`。
- **Flink CEP**：`PATTERN SEQ(A, B, …)`，严格按照列出的顺序，将条件映射到各别名上。

## 支持矩阵

| 关联类型 | Aviator | Flink SQL | Flink CEP |
| -------- | ------- | --------- | --------- |
| `event_count` | ✅ 窗口 + COUNT | ✅ TUMBLE + COUNT | ✅ `SEQ(alias+)` + COUNT |
| `value_count` | ✅ `COUNT_DISTINCT` | ✅ `COUNT(DISTINCT)` | ✅ `COUNT(DISTINCT alias.field)` |
| `temporal` | ✅ `MATCH CO_OCCURRENCE` | ✅ `filtered_events` + `COUNT(DISTINCT rule_name)` | ✅ `SEQ(A, B, …)`（顺序化输出，附提示） |
| `temporal_ordered` | ✅ `MATCH SEQUENCE` | ✅ `MATCH_RECOGNIZE` | ✅ `SEQ(A, B, …)` |

> `✅` 表示自动生成聚合查询；若有警告或提示，会在 `AggregationResult.note` 中说明。

## 限制与注意事项

- CEP 后端当前统一输出顺序模式，`temporal` 类型虽然未要求顺序，但实现上仍使用 `SEQ` 并添加提示，必要时请手工调整。
- CEP 模式对时序关联只保障“每条规则至少命中一次”，因此 `temporal` / `temporal_ordered` 中除了默认 `>=`/`=` 以外的比较符会被回退并产生提示；如需更复杂的匹配逻辑需手工调整 CEP 模式。
- 若关联规则缺乏 `group-by` 或维度信息，所有后端都会在结果中注明需补充分组字段。
- `value_count` 必须提供明确的字段引用；缺失时只返回提示，不生成聚合查询。
- 解析阶段未能解析的规则引用（例如 YAML 中仅给出 `name` 且未与基础规则匹配）不会参与聚合生成。
- 聚合查询默认使用 `event_time`，如数据源字段不同请通过 `metadata.aggregation_event_time_field` 指定。

## 常用扩展点

- **自定义别名**：在 `metadata.aggregation_pattern_alias` 中提供别名，可作用于 CEP 与 Aviator 的模式生成。
- **窗口与阈值覆盖**：通过 `metadata.aggregation_timespan`、`metadata.aggregation_threshold` 可以独立于关联定义覆盖参数。
- **输入校验**：`AggregationResult.note` 会记录阈值调整、缺失信息、别名替换等提示，建议在使用前检查。
