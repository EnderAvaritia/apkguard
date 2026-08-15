# apkguard

Android 恶意行为检测工具（APK / AAB）

一个 Python CLI 工具，检测安卓软件是否会执行恶意行为。**第一版为纯静态分析引擎**
（反编译 APK/AAB 后按规则与特征扫描），**第二版规划动态沙箱**（可插拔后端：
本地模拟器 / 远程 adb 真机 / 第三方沙箱 API，默认禁用且需显式配置）。

## 特性 / Features

- **输入**：APK（完整支持）、AAB（基础支持，实验性——dex 代码分析完整，Manifest 为启发式解析）
- **9 类检测维度**（内置检测器 + YAML 规则库）：
  1. 危险权限 + 敏感 API 调用链
  2. 动态代码加载（DexClassLoader / 反射 / 云端下发载荷）
  3. 无障碍服务滥用（键盘记录 / 自动点击 / 自动授权）
  4. 悬浮窗 / 覆盖攻击（钓鱼界面）
  5. 短信 / 通话恶意行为（扣费短信、短信拦截、号码采集）
  6. 隐私数据外传模式（读敏感数据 + 网络上传同现）
  7. **C2 网络端点分析**（硬编码 IP/域名提取 + 特征打分：纯 IP、非标端口、混淆 URL、DGA、IDN 伪装、内网地址）
  8. 签名 / 证书异常（调试签名、自签名）
  9. 模拟器探测 / 反沙箱 / 反调试识别
- **多档风险阈值**：`--severity low|normal|high`，默认 `low`（宁可多标可疑，不漏恶意）
- **报告输出**：终端详情 / 批量汇总表 / JSON（中英双语标签）/ **自包含单文件 HTML**（可离线转发）
- **隐私硬约束**：默认禁止上传任何数据；一切外部交互（威胁情报 / hash 查询）默认关闭，仅显式配置才启用

## 安装 / Install

```bash
# 虚拟环境（不污染系统 Python）
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## 使用 / Usage

```bash
# 单文件分析：终端输出详情 + 默认生成 <文件名>.json 与 <文件名>.html 报告
# （如 app.apk → app.json / app.html，均按输入文件名命名）
.venv\Scripts\python -m apkguard analyze path/to/app.apk

# 指定报告文件名（覆盖默认命名）
.venv\Scripts\python -m apkguard analyze app.apk --json my_report.json --html my_report.html

# 批量扫描目录（--workers 指定并发，默认自动探测 CPU 核数）
.venv\Scripts\python -m apkguard scan ./apk_folder/

# 指定阈值档位（low 少漏报 / normal 标准 / high 少误报）
.venv\Scripts\python -m apkguard analyze app.apk --severity high

# 自定义规则目录（复制 apkguard/rules/ 后修改）
.venv\Scripts\python -m apkguard analyze app.apk --rules-dir ./my_rules/

# 动态分析（第二阶段，当前仅状态标注）
.venv\Scripts\python -m apkguard dynamic app.apk
```

> Windows 控制台中文乱码时，请使用 Windows Terminal，或先执行 `chcp 65001`。

## 风险分级 / Risk Levels

程序逐项计分累加，按阈值档位分级：

| 档位 | 干净（< 阈值） | 恶意（>= 阈值） | 适用场景 |
|---|---|---|---|
| `low`（默认） | 4 | 8 | 防止漏报，宁可多标可疑 |
| `normal` | 8 | 15 | 标准平衡 |
| `high` | 15 | 25 | 只报警证据确凿，少误报 |

阈值可在 `config.yaml` 中调整。

## 配置 / Configuration

见 `config.yaml` 注释说明。关键项：

- `severity_profiles`：三档阈值
- `test_devices`：**测试设备白名单**（动态分析安全铁律，见下）
- `dynamic`：动态分析参数（初始 5 分钟 / 活跃延长至 15 分钟 / 静默 45 秒收网）
- `enhancements`：可选增强（hash 比对、威胁情报），**默认全部关闭**

## 规则扩展 / Adding Rules

你只需要编辑 `apkguard/rules/*.yaml`，不需要改任何 Python 代码：

```yaml
rules:
  - id: my_new_rule          # 规则 ID（唯一）
    type: permission         # permission | api | string_feature
    title: 中文标题
    title_en: English title
    description: 规则说明
    permission: android.permission.XXX   # permission 类型
    severity: high           # info | low | medium | high | critical
    weight: 3                # 分值
```

复杂检测逻辑（调用链分析、C2 特征组合）已由内置 Python 检测器实现，开箱即用。

## 测试 / Testing

```bash
.venv\Scripts\python -m pytest tests/ -v
```

- **单元测试**：规则引擎、打分分级、9 个检测器、网络端点提取、设备白名单隔离
- **集成测试**：程序化构造合成 APK（合法 AXML + DEX）跑完整分析流水线
- **真实样本回归**（可选）：把你手头的真实样本目录挂入测试验证（样本绝不进 git）

> ⚠️ 安全卫生：`.gitignore` 已强制排除 `samples/` 等目录，真实恶意样本**绝不进入 git**。

## 动态分析（第二阶段规划）/ Dynamic Analysis (Phase 2)

| 维度 | 设计 |
|---|---|
| 后端 | 可插拔：本地 adb 模拟器 / 远程真机 / 第三方沙箱 API（可选，需显式配置） |
| 行为采集 | 网络流量抓包（必做，C2 核心证据）+ Frida hook 敏感 API（有则全量，无则降级系统层） |
| 诱饵数据 | 预置通讯录 + 短信 + 通话记录（`--fake-gps` 开关位置模拟） |
| 交互 | monkey 随机点击兜底 → 定向 UI 自动化为主（弹窗授权优先点允许） |
| 反沙箱 | 不硬刚；探测环境行为本身作为恶意信号上报 + 报告标注环境可信度 |
| 智能终止 | 初始 5 分钟 / 活跃延长至多 15 分钟 / 静默 45 秒提前收网 |

### ★ 测试设备白名单（安全铁律）

程序绝不会碰你的工作设备：

1. **白名单门槛**：只有 `config.yaml` 的 `test_devices` 中显式列出的设备才会被用于运行样本；
   其他 adb 设备（包括你日常连接的模拟器/真机）一律只读不碰，拒绝一切操作
2. **样本不落地工作设备**：恶意样本只安装到白名单测试设备
3. **跑后清理**：动态分析结束自动卸载样本、清理采集文件

`test_devices` 为空时动态分析永不自动触发（默认安全状态）。

### 隐私硬约束

**默认禁止上传任何数据。** 动态分析不会上传 APK；威胁情报 / hash 比对默认关闭，
只有你在配置中显式启用并填入 API key 后才会进行外部网络交互。

## 架构 / Architecture

```
apkguard/
├── cli.py              # 命令行入口（analyze / scan / dynamic）
├── config.py           # 配置加载（config.yaml + CLI 覆盖）
├── static/             # 静态分析
│   ├── apk_parser.py   # APK/AAB 双通道解析（androguard）
│   ├── network_extract.py  # C2 端点提取与特征打分
│   └── detectors/      # 9 个内置检测器（Python 插件）
├── rules/              # YAML 规则库（用户可编辑）
├── engine/             # 规则引擎 / 打分分级 / 数据模型
├── dynamic/            # 动态分析接口（第二阶段执行体）
│   ├── backend.py          # 可插拔后端抽象
│   └── device_manager.py   # 测试设备白名单隔离（安全核心）
└── output/             # 终端 / JSON / HTML 报告
```

## 技术栈 / Tech Stack

Python 3.10+ · androguard 4.1.4 · PyYAML · pytest

## 开发状态 / Roadmap

- [x] 第一版：静态分析引擎（解析 / 9 检测器 / 规则引擎 / 报告 / 测试）
- [ ] 第二阶段：动态分析执行体（adb 后端 + 流量抓包 + Frida 采集 + UI 自动化）
- [ ] 增强：壳检测（apkid 特征库）、本地 hash 比对、威胁情报查询（默认关闭）
- [ ] AAB Manifest 精确 protobuf 解析（待真实样本验证）
