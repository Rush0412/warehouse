# Sigma 规则全维度详解（字段、结构、关键字、关联规则与类型）

基于 Sigma 官方文档（sigmahq.io）及社区规范，从**基础 Sigma 规则**和**关联规则（Correlations）** 两大维度，系统梳理字段、结构、关键字及关联设计细节。

## 一、基础 Sigma 规则（非关联规则）

基础 Sigma 规则是检测单类事件的核心模板，遵循 “标准化元数据 + 日志源定义 + 检测逻辑” 结构，所有规则均以 YAML 格式编写，分为**必填字段**和**可选字段**。

### 1. 基础规则核心结构

yaml

```yaml
title: 规则标题（必填）
id: 全局唯一ID（可选，推荐UUID v4）
status: 规则状态（可选，如experimental/testing/stable）
description: 规则描述（可选）
author: 作者（可选）
references: 参考链接（可选，数组形式）
logsource: 日志源（必填，定义日志来源）
  category: 日志类别（可选，如process_creation/firewall）
  product: 产品（必填，如windows/linux/cisco）
  service: 服务（必填，如security/sysmon/sshd）
detection: 检测逻辑（必填，核心部分）
  selection: 事件匹配条件（自定义标识符，如selection/filter/exclude）
    FieldName1: 匹配值1（支持字符串、数组、修饰符）
    FieldName2|modifier: 匹配值2（如endswith/contains）
  timeframe: 时间窗口（可选，如5m/1h，用于聚合检测）
  condition: 触发条件（必填，定义如何触发告警）
falsepositives: 误报场景（可选，数组/字符串）
level: 告警级别（可选，informational/low/medium/high/critical）
tags: 标签（可选，数组形式，如MITRE ATT&CK标签）
fields: 需展示的关键字段（可选，数组形式，如TargetUserName/src_ip）
```

### 2. 基础规则字段详解（含必填 / 可选、作用与示例）

| 字段名           | 必填 / 可选  | 类型          | 核心作用                                            | 示例与说明                                                   |
| ---------------- | ------------ | ------------- | --------------------------------------------------- | ------------------------------------------------------------ |
| `title`          | 必填         | 字符串        | 简洁描述规则检测目标（≤256 字符）                   | `title: Windows Failed Logon (EventID 4625)`                 |
| `id`             | 可选（推荐） | 字符串        | 全局唯一标识，避免规则冲突                          | `id: 929a690e-bef0-4204-a928-ef5e620d6fcc`（UUID v4，推荐用[UUID 生成器](https://www.uuidgenerator.net/)） |
| `status`         | 可选         | 枚举          | 规则成熟度，用于筛选和版本管理                      | `status: experimental`（可选值：`experimental`/`testing`/`stable`） |
| `description`    | 可选         | 字符串        | 详细说明检测场景、目的及攻击背景                    | `description: Detects failed logon events on Windows systems via Security log EventID 4625` |
| `author`         | 可选         | 字符串 / 数组 | 规则作者（姓名 / 邮箱）                             | `author: John Doe (john.doe@example.com)`                    |
| `references`     | 可选         | 数组          | 参考文档（如 MITRE ATT&CK、漏洞公告）               | `references: [- https://attack.mitre.org/techniques/T1110/, - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-22518]` |
| `logsource`      | 必填         | 嵌套结构      | 定义日志来源，决定规则适用的日志范围                | 示例：`logsource:``product: windows``service: security``category: logon`（`category`可选，用于细分日志类型） |
| `detection`      | 必填         | 嵌套结构      | 核心检测逻辑，包含 “匹配条件 + 时间窗口 + 触发条件” | 详见下文 “detection 关键字与逻辑”                            |
| `falsepositives` | 可选         | 字符串 / 数组 | 常见误报场景，帮助分析师排查                        | `falsepositives: [- Administrative activity, - Directory assessment tools]` |
| `level`          | 可选         | 枚举          | 告警优先级，指导响应流程                            | `level: high`（可选值：`informational`/`low`/`medium`/`high`/`critical`） |
| `tags`           | 可选         | 数组          | 规则分类标签（如 MITRE ATT&CK、技术类型）           | `tags: [- attack.t1110, - brute_force, - windows]`           |
| `fields`         | 可选         | 数组          | 告警触发时需展示的关键字段（便于溯源）              | `fields: [- TargetUserName, - TargetDomainName, - src_ip]`   |

### 3. `detection`核心关键字与逻辑

`detection`是基础规则的核心，包含**自定义匹配标识符**（如`selection`/`filter`）、**时间窗口**（`timeframe`）和**触发条件**（`condition`），支持复杂逻辑组合。

#### （1）自定义匹配标识符

- 作用：定义事件的 “包含条件”（`selection`）、“排除条件”（`filter`）等，标识符名称可自定义（如`bad_process`/`suspicious_ip`）。
- 逻辑规则：
  - **数组形式**：元素间为 “OR” 逻辑（匹配任意一个值）；
  - **Map 形式**：键值对间为 “AND” 逻辑（需同时满足所有键值对）；
  - **修饰符**：通过`|`添加字段修饰符，支持常见匹配逻辑。

| 修饰符       | 作用                   | 示例             |                                  |
| ------------ | ---------------------- | ---------------- | -------------------------------- |
| `endswith`   | 字段值以指定字符串结尾 | `SubjectUserName | endswith: $`（匹配机器账户）     |
| `startswith` | 字段值以指定字符串开头 | `Image           | startswith: C:\Windows\System32` |
| `contains`   | 字段值包含指定字符串   | `CommandLine     | contains: powershell.exe`        |
| `regex`      | 字段值匹配正则表达式   | `UserAgent       | regex: ^Mozilla/5.0.*Chrome/`    |
| `not`        | 排除指定值（取反）     | `EventID         | not: 4624`（排除成功登录事件）   |

#### （2）`timeframe`：时间窗口

- 作用：定义 “在指定时间内” 聚合事件（仅用于需要统计频率的场景）；
- 格式：支持`s`（秒）、`m`（分）、`h`（时），如`5m`（5 分钟）、`1h`（1 小时）；
- 示例：`timeframe: 10s`（10 秒内的事件参与聚合）。

#### （3）`condition`：触发条件

- 作用：定义 “何时触发告警”，支持逻辑运算符（`and`/`or`/`not`）、聚合函数（`count`/`min`/`max`）及通配符（`*`）。
- 常见写法：
  1. 直接引用匹配标识符：`condition: selection`（满足`selection`即触发）；
  2. 逻辑组合：`condition: selection and not filter`（满足`selection`且不满足`filter`）；
  3. 聚合计数：`condition: selection | count > 10`（10 秒内`selection`匹配事件超 10 次，需配合`timeframe`）；
  4. 多标识符组合：`condition: (selection1 or selection2) and filter`。

## 二、Sigma 关联规则（Correlations）

关联规则是 “基于基础规则的进阶检测”，用于分析**多类事件间的关系**（如时间共存、频率异常），属于 Sigma Meta Rules 范畴，核心是通过`correlation`字段替代基础规则的`detection`字段。

### 1. 关联规则设计原则

1. **依赖基础规则**：关联规则必须引用 1 个及以上基础规则（通过`name`或`id`），基础规则需与关联规则在同一文件（用`---`分隔）或转换时单独提供；
2. **无`logsource`字段**：关联规则的日志源继承自引用的基础规则，无需单独定义；
3. **SIEM 支持有限**：目前仅支持 Splunk SPL、Elasticsearch ES|QL、Grafana Loki 查询语言；
4. **默认隐藏基础规则**：转换为 SIEM 查询时，默认仅保留关联逻辑；若需保留基础规则，需添加`generate: true`。

### 2. 关联规则核心结构

yaml

```yaml
title: 关联规则标题（必填）
status: 规则状态（可选，如test/experimental）
correlation: 关联逻辑（必填，核心部分）
  type: 关联类型（必填，如event_count/temporal）
  rules: 引用的基础规则列表（必填，通过name或id）
  group-by: 事件分组字段（可选，数组形式，如TargetUserName/src_ip）
  timespan: 事件聚合时间范围（必填，如5m/10s）
  condition: 关联匹配条件（必填，如gte: 10）
  generate: 是否保留基础规则（可选，true/false，默认false）
  aliases: 字段别名（可选，跨日志源字段映射）
tags: 标签（可选，如attack.t1110/brute_force）
level: 告警级别（可选，同基础规则）
falsepositives: 误报场景（可选，同基础规则）
```

### 3. 关联规则字段详解

| 字段名        | 必填 / 可选 | 类型     | 核心作用                                   | 示例与说明                                                   |
| ------------- | ----------- | -------- | ------------------------------------------ | ------------------------------------------------------------ |
| `correlation` | 必填        | 嵌套结构 | 关联规则的核心逻辑容器                     | 包含`type`/`rules`/`timespan`等子字段，替代基础规则的`detection` |
| `type`        | 必填        | 枚举     | 关联类型，决定事件关系的分析逻辑           | `type: event_count`（可选值：`event_count`/`value_count`/`temporal`/`ordered_temporal`） |
| `rules`       | 必填        | 数组     | 引用的基础规则列表（通过基础规则的`name`） | `rules: [- failed_logon, - privileged_group_enumeration]`（需确保基础规则的`name`为对应值） |
| `group-by`    | 可选        | 数组     | 按指定字段分组聚合事件（如按用户 / IP）    | `group-by: [- TargetUserName, - TargetDomainName]`（分析单个用户的事件） |
| `timespan`    | 必填        | 字符串   | 定义 “多久内的事件视为相关”                | `timespan: 5m`（5 分钟内的事件参与关联）、`timespan: 10s`（10 秒内） |
| `condition`   | 必填        | 嵌套结构 | 关联触发的阈值条件                         | 示例 1（`event_count`）：`condition: {gte: 10}`（事件数≥10）；示例 2（`value_count`）：`condition: {gte: 4, field: TargetUserName}`（字段不同值数≥4） |
| `generate`    | 可选        | 布尔值   | 转换时是否保留基础规则的查询逻辑           | `generate: true`（默认 false，保留基础规则便于调试）         |
| `aliases`     | 可选        | 嵌套结构 | 跨日志源字段映射（解决字段名不一致问题）   | 示例：`aliases:``ip:``rule_with_src_ip: src_ip``rule_with_dest_ip: dest_ip`（将两个规则的不同字段映射为虚拟字段`ip`） |

### 4. 字段别名（Aliases）使用场景与示例

当引用的基础规则 “字段含义相同但名称不同” 时（如 A 规则用`src_ip`，B 规则用`dest_ip`），需通过`aliases`定义**虚拟字段**实现关联：

- 核心逻辑：将多个基础规则的不同字段映射为同一个虚拟字段，用于`group-by`聚合；

- 示例（检测 “同一 IP 的访问与攻击事件”）：

  yaml

  ```yaml
  correlation:
    type: temporal
    rules:
      - web_access_rule  # 基础规则1，字段为src_ip
      - attack_rule      # 基础规则2，字段为dest_ip
    aliases:
      ip:  # 虚拟字段ip
        web_access_rule: src_ip  # 规则1的src_ip映射到ip
        attack_rule: dest_ip     # 规则2的dest_ip映射到ip
    group-by:
      - ip  # 按虚拟字段ip分组
    timespan: 5m
    condition: {}  # temporal类型无需阈值，存在即触发
  ```

  

## 三、Sigma 关联类型（4 种核心类型）

关联类型决定 “如何分析多事件关系”，每种类型对应明确的检测场景，需根据业务需求选择。

### 1. `event_count`：事件计数关联

#### 核心逻辑

统计 “同一分组、同一时间窗口内” 基础规则匹配的**事件总数**，判断是否超过阈值（如 “5 分钟内同一用户登录失败超 10 次”）。

#### 适用场景

- 暴力破解攻击（登录失败次数超阈值）；
- 拒绝服务攻击（连接请求数超阈值）；
- 日志源故障（事件数低于阈值，如某服务器突然停止产生日志）。

#### 完整示例（Windows 暴力破解检测）

yaml

```yaml
sigma: 2.0
title: Windows Failed Logon Event
id: 9f9b9a7e-8c3f-4d1c-9a3e-6b3ca6f9a7e1
name: failed_logon  # 关联规则将引用此 name
status: test
description: 单条 4625 失败登录事件，排除以 $ 结尾的机器账户
author: you
date: 2025-10-09

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625
  filter_machine:
    SubjectUserName|endswith: "$"   # 排除机器账户
  condition: selection and not filter_machine

level: medium
tags:
  - windows
  - security
  - auth.fail
  - event.4625
fields:
  - TargetUserName
  - TargetDomainName
  - SubjectUserName
---
sigma: 2.0
title: Multiple Failed Logons (Possible Brute Force)
id: 3b1dd9b1-5e74-44bc-9b5f-2d9d4e6c1f10
status: test
description: 5 分钟内同一用户（域+用户名）登录失败次数 ≥ 10
author: you
date: 2025-10-09

correlation:
  type: event_count
  rules:
    - failed_logon            # 按 name 引用上面的基础规则
  group-by:
    - TargetUserName
    - TargetDomainName
  timespan: 5m
  condition:
    gte: 10

level: high
tags:
  - attack.t1110
  - brute_force

```

### 2. `value_count`：字段值多样性关联

#### 核心逻辑

统计 “同一分组、同一时间窗口内” 基础规则中**某字段的不同值数量**（如 “15 分钟内同一用户枚举 4 个高权限组”）。

#### 适用场景

- 高权限组枚举（如 BloodHound 工具扫描 AD 组）；
- 多 IP 登录同一账号（如同一用户从 5 个不同 IP 登录）；
- 多目标攻击（如同一 IP 扫描 10 个不同端口）。

#### 完整示例（BloodHound 枚举检测）

yaml

```yaml
sigma: 2.0
title: High-Privilege Group Enumeration
id: 2f9f4f3e-0b6a-4d2f-9f4b-7b0a2c9e4f79
name: privileged_group_enumeration
status: test
description: 检测 Windows 高权限组枚举（EventID 4799），限定 CallerProcessId 为 0x0，目标组为常见高权限组。
author: you
date: 2025-10-09

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4799
    CallerProcessId: "0x0"
    TargetUserName:
      - "Administrators"
      - "Remote Desktop Users"
      - "Remote Management Users"
      - "Distributed COM Users"
  condition: selection

level: informational
tags:
  - windows
  - discovery
  - event.4799
fields:
  - SubjectUserName
  - TargetUserName
  - CallerProcessId
  - EventID
---
sigma: 2.0
title: BloodHound Group Enumeration Detection
id: 6a1eaa91-3c7c-4e4e-9f27-5a2f2c3b8d55
status: test
description: 15 分钟内同一用户枚举的高权限组去重数量 ≥ 4（疑似 BloodHound/组枚举行为）
author: you
date: 2025-10-09

correlation:
  type: value_count
  rules:
    - privileged_group_enumeration   # 按 name 引用上面的基础规则
  group-by:
    - SubjectUserName                # 按枚举发起用户分组
  timespan: 15m
  condition:
    field: TargetUserName            # 对不同组名去重计数
    gte: 4

level: high
tags:
  - attack.discovery
  - bloodhound
falsepositives:
  - Administrative activity
```

### 3. `temporal`：时间共存关联

#### 核心逻辑

判断 “多种不同基础规则” 是否在**同一时间窗口内共存**（不要求事件顺序，如 “访问漏洞端点 + 创建可疑进程”）。

#### 适用场景

- 漏洞利用链（如 CVE-2023-22518：访问漏洞端点 + Tomcat 创建 cmd 进程）；
- 成功暴力破解（失败登录 + 成功登录在同一时间窗口）；
- 横向移动（远程登录 + 进程创建在同一主机）。

#### 完整示例（CVE-2023-22518 漏洞利用检测）

yaml

```yaml
sigma: 2.0
title: Confluence Vulnerable Endpoint Access
id: a902d249-9b9c-4dc4-8fd0-fbe528ef965c
name: confluence_vuln_access
status: test
description: Access to known vulnerable Confluence setup/restore endpoints with successful or redirected responses.
author: you
date: 2025-10-09

logsource:
  product: confluence
  service: web

detection:
  selection:
    cs-method: 'POST'
    cs-uri-query:
      - '*/json/setup-restore-local.action*'
      - '*/setup/setupadministrator.action*'
    sc-status:
      - 200
      - 302
      - 405
  condition: selection

level: medium
tags:
  - cve.2023-22518
  - confluence
  - web

fields:
  - cs-method
  - cs-uri-query
  - sc-status
---
sigma: 2.0
title: Suspicious Process Creation by Tomcat
id: 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db
name: tomcat_suspicious_process
status: test
description: Tomcat spawning command interpreters with Confluence-related command line (possible webshell / exploit post-exec).
author: you
date: 2025-10-09

logsource:
  product: windows
  service: sysmon

detection:
  selection:
    ParentImage:
      - '*\tomcat8.exe'
      - '*\tomcat9.exe'
    ParentCommandLine: '*confluence*'
    Image:
      - '*\cmd.exe'
      - '*\powershell.exe'
  condition: selection

level: medium
tags:
  - windows
  - sysmon
  - process_creation
  - confluence

fields:
  - ParentImage
  - ParentCommandLine
  - Image
---
sigma: 2.0
title: CVE-2023-22518 Exploit Chain
id: 6b6e2a6c-3d5e-4a0e-8d8a-4f2b6a7c9f10
status: test
description: Within 10 seconds, see vulnerable Confluence endpoint access and a Tomcat-spawned shell on the host (possible CVE-2023-22518 exploitation).
author: you
date: 2025-10-09

correlation:
  type: temporal
  rules:
    - confluence_vuln_access
    - tomcat_suspicious_process
  timespan: 10s
  condition: all

level: critical
tags:
  - cve.2023-22518
  - attack.initial_access
  - attack.execution

```

### 4. temporal_ordered：有序时间关联

#### 核心逻辑

在`temporal`基础上增加**事件顺序要求**（如 “先失败登录→后成功登录”），需严格满足 “事件 A 发生在事件 B 之前”。

#### 适用场景

- 强依赖顺序的攻击（如 “先执行命令注入→再写入后门文件→最后反弹 shell”）；
- 特定操作流程异常（如 “先注销账户→后登录账户”，不符合正常操作顺序）。

#### 关键注意事项（需谨慎使用）

1. **性能差**：判断事件顺序的查询复杂度远高于`temporal`，易导致 SIEM 性能瓶颈；
2. **时钟偏差风险**：不同日志源（如 Web 服务器、数据库）的时钟可能不同步，导致事件顺序判断错误；
3. **多数场景无需顺序**：多数攻击检测中，“时间共存” 已足够（如失败登录 + 成功登录无论顺序均需警惕）；
4. **SIEM 支持有限**：部分 SIEM（如早期 ELK）无法通过查询语言实现事件顺序判断。

#### 示例（简化版：先失败登录→后成功登录）

yaml

```yaml
# ============ 基础规则 A：失败登录（4625） ============
sigma: 2.0
title: Windows Failed Logon Event
id: 5b6b1b2e-5a2b-4f83-8f12-1c2a3b4d5e60
name: failed_logon
status: test
author: you
date: 2025-10-10
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: low
tags: [windows, auth.fail]
fields: [TargetUserName, src_ip]

---
# ============ 基础规则 B：成功登录（4624） ============
sigma: 2.0
title: Windows Successful Logon Event
id: 7c1a5f4d-2e6b-4d1a-9a73-8a0a21f0f302
name: success_logon
status: test
author: you
date: 2025-10-10
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
  condition: selection
level: low
tags: [windows, auth.success]
fields: [TargetUserName, src_ip]

---
# ===== 关联规则：ordered_temporal（A→B，5m 内） =====
sigma: 2.0
title: Failed-Then-Success Logon within 5m (Ordered Temporal)
id: 9f0b2e9d-4b2b-4c5e-8a7e-1f9d3c2b7403
status: test
author: you
date: 2025-10-10
correlation:
  type: temporal_ordered
  rules:
    - failed_logon      # 先发生
    - success_logon     # 后发生
  group-by:
    - src_ip
    - TargetUserName
  timespan: 5m
  # condition 可省略；如需显式写法可用：
  # condition: all
level: high
tags: [windows, brute_force.followed_by_success, detection.ordered_temporal]

```

## 三、核心关键字汇总（基础 + 关联规则）

| 关键字           | 所属规则类型 | 核心作用         | 关键属性 / 示例                                           |
| ---------------- | ------------ | ---------------- | --------------------------------------------------------- |
| `title`          | 所有规则     | 规则标题         | `title: Windows Failed Logon`                             |
| `id`             | 所有规则     | 全局唯一标识     | `id: 929a690e-bef0-4204-a928-ef5e620d6fcc`                |
| `logsource`      | 基础规则     | 定义日志来源     | `product: windows, service: security`                     |
| `detection`      | 基础规则     | 单事件检测逻辑   | `selection`, `timeframe`, `condition`                     |
| `correlation`    | 关联规则     | 多事件关联逻辑   | `type`, `rules`, `timespan`, `group-by`                   |
| `type`           | 关联规则     | 关联类型         | `event_count`, `temporal`                                 |
| `rules`          | 关联规则     | 引用基础规则列表 | `[- failed_logon, - success_logon]`                       |
| `group-by`       | 关联规则     | 事件分组字段     | `[- TargetUserName, - src_ip]`                            |
| `timespan`       | 关联规则     | 时间窗口         | `5m`, `10s`                                               |
| `condition`      | 所有规则     | 触发条件         | 基础规则：`selection and not filter`；关联规则：`gte: 10` |
| `aliases`        | 关联规则     | 字段别名映射     | `ip: {rule1: src_ip, rule2: dest_ip}`                     |
| `generate`       | 关联规则     | 保留基础规则     | `true`/`false`                                            |
| `status`         | 所有规则     | 规则成熟度       | `experimental`, `stable`                                  |
| `level`          | 所有规则     | 告警级别         | `high`, `critical`                                        |
| `tags`           | 所有规则     | 规则分类标签     | `attack.t1110`, `brute_force`                             |
| `falsepositives` | 所有规则     | 误报场景         | `[- Administrative activity]`                             |