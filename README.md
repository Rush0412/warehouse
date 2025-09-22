# Sigma Rule Service

FastAPI 后端服务，基于 [pysigma](https://github.com/SigmaHQ/pySigma) 实现对 sigma 规则的解析、验证与多格式转换能力，满足与开源 sigma 规范严格兼容的需求。

## 功能特性

- **规则解析**：接收前端提交的 YAML 格式 sigma 规则，返回结构化数据。
- **规则验证**：基于 pysigma 完成语法校验，并执行额外的必填字段检测。
- **规则转换**：支持 Aviator、Flink SQL、Flink CEP 三种目标格式，采用适配器模式，便于后续扩展更多引擎。
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
uvicorn app.main:app --reload
```

服务启动后可通过 `http://localhost:8000/docs` 访问自动生成的 OpenAPI 文档。

## API 概览

| 方法 | 路径 | 描述 |
| ---- | ---- | ---- |
| `POST` | `/rules/parse` | 解析 YAML 格式的 sigma 规则 |
| `POST` | `/rules/validate` | 校验 sigma 规则是否符合规范 |
| `POST` | `/rules/convert` | 将单条规则转换为目标格式 |
| `POST` | `/rules/convert/batch` | 批量转换多条规则 |
| `GET` | `/health` | 健康检查 |

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
