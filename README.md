# Sigma Rule Service

FastAPI 后端服务，基于 [pysigma](https://github.com/SigmaHQ/pySigma) 实现对 sigma 规则的解析、验证与多格式转换能力，满足与开源 sigma 规范严格兼容的需求。

## 功能特性

- **规则解析**：接收前端提交的 YAML 格式 sigma 规则，返回结构化数据。
- **规则验证**：基于 pysigma 完成语法校验，并执行额外的必填字段检测。
- **规则转换**：支持 Aviator、Flink SQL、Flink CEP 三种目标格式，采用适配器模式，便于后续扩展更多引擎。
- **统一输出**：解析接口会同步返回所有注册后端的转换结果，默认包含 Aviator/Flink SQL/Flink CEP。
- **批量处理**：提供批量转换接口，满足大规模规则转换场景。
- **扩展预留**：模块化设计，解耦解析、转换与接口层，预留持久化与 Flink 扩展点。

## 快速开始

### 1. 创建虚拟环境并安装依赖

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. 启动服务

```bash
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

服务启动后可通过 `http://localhost:8000/docs` 访问自动生成的 OpenAPI 文档。

## API 概览

| 方法   | 路径                   | 描述                        |
| ------ | ---------------------- | --------------------------- |
| `POST` | `/rules/parse`         | 解析 YAML 格式的 sigma 规则 |
| `POST` | `/rules/validate`      | 校验 sigma 规则是否符合规范 |
| `POST` | `/rules/convert`       | 将单条规则转换为目标格式    |
| `POST` | `/rules/convert/batch` | 批量转换多条规则            |
| `GET`  | `/health`              | 健康检查                    |

## 请求示例

```json
POST /rules/convert
{
  "payload": {
    "rule_yaml": "title: Suspicious Process\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection"
  },
  "target_format": "flink_sql",
  "options": {
    "table": "processed_events"
  }
}
```

## 设计亮点

- **适配器模式**：`app/converters` 目录中的转换器实现可以按需新增，`SigmaConverterService` 会自动注册默认实现。
- **检测表达式构建器**：`DetectionExpressionBuilder` 将 sigma detection 转换为布尔表达式，为多种后端引擎复用逻辑。
- **持久化扩展**：`SigmaRuleRepository` 抽象类定义了规则存储接口，可替换为数据库或版本控制实现。

## 测试

项目提供基础测试依赖，可在安装 `dev` 额外依赖后执行：

```bash
pytest
```

> 由于执行环境限制（离线），安装 pysigma 可能需要在联网环境中完成。

### 解析示例响应

```json
{
  "parsed": { "title": "Example rule", "detection": { "condition": "selection" } },
  "conversions": [
    { "format": "aviator", "query": "..." },
    { "format": "flink_sql", "query": "..." },
    { "format": "flink_cep", "query": "..." }
  ],
  "errors": null
}
```

> `conversions` 数组来源于 pysigma 的解析结果，会根据注册的转换后端自动扩展。

### 转换示例请求

```json
{
  "payload": {
    "rule_yaml": "title: Suspicious Process\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: powershell.exe\n  condition: selection"
  },
  "target_format": "flink_sql",
  "options": {
    "table": "processed_events"
  }
}
```

对应响应：

```json
{
  "format": "flink_sql",
  "query": "SELECT * FROM processed_events WHERE ENDS_WITH(Image, 'powershell.exe');"
}
```


## Sigma Correlation 支持

- 服务现已集成 `sigma.correlations`，`app/services/parser.py` 会同时解析 `SigmaRule` 与 `SigmaCorrelationRule`，确保聚合/关联规则通过“解析”“校验”流程。
- 解析阶段会自动清洗非规范标签（收纳至 `metadata.custom_tags`），并在缺省时为关联规则补齐 `timespan`、`condition`，以及根据 `metadata.dimensions` 补全 `group-by`。
- 解析、转换接口会在 `aggregation` 字段中返回时间窗口、分组与阈值信息，便于直接复用聚合查询。
- 可选的 `metadata.aggregation_event_time_field` 和 `metadata.aggregation_pattern_alias` 可分别指定 Flink SQL 使用的事件时间字段以及 CEP 输出的模式别名。
- 可通过 `metadata.aggregation_timespan` 与 `metadata.aggregation_threshold` 配置统计窗口和阈值；未提供时默认 `5m` 与 `gte: 1`。
- 转换流程 (`app/services/converter.py`) 仍只针对普通 `SigmaRule` 生成查询，聚合规则会保留在原始 YAML 中供业务侧二次处理。
- 建议将平台特有信息放入 `metadata`，并使用标准 Sigma 命名空间标签（例如 `attack.*`）；其它标签将出现在 `metadata.custom_tags` 中，避免 pysigma 校验报错。

```yaml
title: 非法网络行为聚合检测
id: 123e4567-e89b-12d3-a456-426614174000
logsource:
  product: detection_platform
  service: intel_engine
detection:
  selection:
    attack_status: "失陷"
    engine_type: intel
  condition: selection
tags:
  - attack.t1219
metadata:
  rule_id: RULE-20
  rule_name: 聚合-情报类-失陷聚合
  display_name: 非法网络行为聚合
  priority: 50
  dimensions:
    - src_ip
    - ioc
    - attack_status
  aggregation_timespan: 10m
  aggregation_event_time_field: log_time
  aggregation_pattern_alias: EVENT
  aggregation_threshold: 3
---
title: 非法网络行为聚合统计
id: 223e4567-e89b-12d3-a456-426614174000
correlation:
  type: event_count
  rules: 123e4567-e89b-12d3-a456-426614174000
  group-by:
    - src_ip
    - ioc
    - attack_status
metadata:
  rule_id: RULE-20
  rule_name: 聚合-情报类-失陷聚合
  display_name: 非法网络行为聚合
  aggregation_pattern_alias: EVENT
  priority: 50
  dimensions:
    - src_ip
    - ioc
    - attack_status
```

- 如果在 YAML 中省略 `correlation.timespan` 或 `correlation.condition`，服务会依据 `metadata` 中的配置或默认值自动补齐，确保 pysigma 校验顺利通过。
