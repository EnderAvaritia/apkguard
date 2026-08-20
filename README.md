# apkguard

Android 恶意行为检测工具（APK / AAB）

一个 Python CLI 工具，检测安卓软件是否会执行恶意行为。**静态分析引擎**已成熟
（反编译 APK/AAB 后按规则与特征扫描）；**动态分析执行体**（v1）已落地
（可插拔 adb 后端：本地模拟器 / 真机，默认禁用且需显式配置，见下文）。

## 特性 / Features

- **输入**：APK（完整支持）、AAB（基础支持，实验性——dex 代码分析完整，Manifest 为启发式解析）
- **10 类检测维度**（内置检测器 + YAML 规则库）：
  1. 危险权限 + 敏感 API 调用链
  2. 动态代码加载（DexClassLoader / 反射 / 云端下发载荷）
  3. 无障碍服务滥用（键盘记录 / 自动点击 / 自动授权）
  4. 悬浮窗 / 覆盖攻击（钓鱼界面）
  5. 短信 / 通话恶意行为（扣费短信、短信拦截、号码采集）
  6. 隐私数据外传模式（读敏感数据 + 网络上传同现）
  7. **C2 网络端点分析**（硬编码 IP/域名提取 + 特征打分：纯 IP、非标端口、混淆 URL、DGA、IDN 伪装、内网地址）
  8. 签名 / 证书异常（调试签名、自签名）
  9. 模拟器探测 / 反沙箱 / 反调试识别
  10. **数据破坏性操作**（跨目录读写系统/其他应用数据、删库 DROP/DELETE、设备管理器远程擦除）
- **多档风险阈值**：`--severity low|normal|high`，默认 `low`（宁可多标可疑，不漏恶意）
- **报告输出**：终端详情 / 批量汇总表 / JSON（中英双语标签）/ **自包含单文件 HTML**（标签页布局，可离线转发）
- **低内存解析**：dex 分析用轻量方法引用表（method_ids）替代完整调用图（xref），
  单文件内存占用降约 58%——186MB 大 APK 也可单机分析
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
# （如 app.apk → reports/app.json / reports/app.html，统一输出到 reports/ 目录，
#   该目录已被 .gitignore 忽略，报告不进版本控制）
.venv\Scripts\python -m apkguard analyze path/to/app.apk

# 指定报告文件名（覆盖默认命名与默认 reports/ 目录）
.venv\Scripts\python -m apkguard analyze app.apk --json my_report.json --html my_report.html

# 批量扫描目录（--workers 指定并发，默认自动探测 CPU 核数；多进程隔离，按文件大小自适应限流防 OOM）
# 结束后自动输出 reports/scan_summary.json / reports/scan_summary.html 批量汇总报告
.venv\Scripts\python -m apkguard scan ./apk_folder/

# 批量扫描时同时逐样本输出 JSON 报告到指定目录
.venv\Scripts\python -m apkguard scan ./apk_folder/ --json-dir ./per_sample_json/

# 指定阈值档位（low 少漏报 / normal 标准 / high 少误报）
.venv\Scripts\python -m apkguard analyze app.apk --severity high

# 自定义规则目录（复制 apkguard/rules/ 后修改）
.venv\Scripts\python -m apkguard analyze app.apk --rules-dir ./my_rules/

# 自定义配置文件（默认读取 ./config.yaml，可指定其他路径）
.venv\Scripts\python -m apkguard analyze app.apk --config ./my_config.yaml

# 动态分析（第二阶段）：需先在 config.yaml 开启 dynamic.enabled 并配置测试设备
# 默认自动输出 reports/<输入名>.json 与 reports/<输入名>.html 报告（--json/--html 可指定路径）
.venv\Scripts\python -m apkguard dynamic app.apk

# 显式指定 adb 设备（绕过 test_devices 白名单；报告会标注"绕过白名单"）
.venv\Scripts\python -m apkguard dynamic app.apk --device emulator-5554
.venv\Scripts\python -m apkguard analyze app.apk --device 0123456789ABCDEF

# 跳过静态检测与打分，只解析包名/权限后直接动态分析（样本大/只关心动态行为时提速）
.venv\Scripts\python -m apkguard dynamic app.apk --device emulator-5554 --no-static
```

> Windows 控制台中文乱码时，请使用 Windows Terminal，或先执行 `chcp 65001`。

## 运行日志 / Runtime Logs

工具运行日志（进度）统一输出到 **stderr**（与报告 stdout 分离），格式
`HH:MM:SS LEVEL message`（INFO 级）：

- **静态分析进度**（`analyze` / `scan`）：解析阶段逐 dex 输出
  `Parsing APK: app.apk (80.1 MB)` → `Manifest parsed` → `Parsing dex 3/11 (7.6 MB)` → …
  检测器逐项输出 `detector 3/10: C2 network endpoint analysis (c2_network)`，
  最终 `Detectors done: N findings`。大样本跑几十秒期间也有持续反馈，不会"看着像卡死"。
- **动态分析实时日志**（`dynamic`）：安装 / 权限预授权 / 诱饵数据 / 代理抓包 /
  交互（monkey）/ 智能终止收网等执行步骤逐条输出。
- **批量扫描进度**（`scan`）：主进程输出 `scan progress: i/N files done`。
- **androguard 刷屏压制**：androguard 解析 APK/DEX 时会经 loguru 输出海量调试日志
  （80MB 样本实测约 20 万行），`analyze` / `scan` / `dynamic` 及 scan 各 worker
  子进程均默认压制，仅保留 WARNING 及以上——终端不再被垃圾日志淹没。

## 风险分级 / Risk Levels

程序逐项计分累加，按阈值档位分级：

| 档位 | 干净（< 阈值） | 恶意（>= 阈值） | 适用场景 |
|---|---|---|---|
| `low`（默认） | 4 | 8 | 防止漏报，宁可多标可疑 |
| `normal` | 8 | 15 | 标准平衡 |
| `high` | 15 | 25 | 只报警证据确凿，少误报 |

阈值可在 `config.yaml` 中调整。

## 配置 / Configuration

首次使用先复制模板为本地私有配置：

```bash
copy config.example config.yaml    # Windows
cp config.example config.yaml      # Linux/macOS
```

> `config.yaml` 已被 `.gitignore` 忽略——它包含 `test_devices`（设备序列号）等本机私有信息，
> 不进版本控制；模板与全部可配置项见 `config.example`。

见 `config.yaml` 注释说明。关键项：

- `severity_profiles`：三档阈值
- `rules_dir`：YAML 规则目录（可被 `--rules-dir` 覆盖）
- `scan_workers`：批量扫描并发数（0 = 自动探测 CPU 核数，可被 `--workers` 覆盖）
- `test_devices`：**测试设备白名单**（动态分析安全铁律，见下）
- `dynamic`：动态分析参数（初始 5 分钟 / 活跃延长至 15 分钟 / 静默 45 秒收网 /
  代理抓包 / Frida / 诱饵数据 / 同包名处理 / 手动登录门等，含 `replace_existing`、
  `cleanup_uninstall` 与 `manual_login`）
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

- **单元测试**：规则引擎、打分分级、10 个检测器、网络端点提取、设备白名单隔离
- **集成测试**：程序化构造合成 APK（合法 AXML + DEX）跑完整分析流水线
- **真实样本回归**（可选）：把你手头的真实样本目录挂入测试验证（样本绝不进 git）

> ⚠️ 安全卫生：`.gitignore` 已强制排除 `samples/` 等目录，真实恶意样本**绝不进入 git**。

## 动态分析（第二阶段）/ Dynamic Analysis (Phase 2)

> **实现状态**：执行体已落地（v1）。`dynamic` 命令在 `dynamic.enabled: true`
> 且有目标设备（白名单或 `--device` 显式指定）时真正安装运行样本；
> `analyze` / `scan` 仍只做状态标注，不执行样本。

| 维度 | 设计 |
|---|---|
| 后端 | 可插拔：本地 adb 模拟器 / 远程真机 / 第三方沙箱 API（可选，需显式配置） |
| 行为采集 | 网络流量抓包（必做，C2 核心证据）+ Frida hook 敏感 API（有则全量，无则降级系统层） |
| 诱饵数据 | 预置通讯录 + 短信 + 通话记录（`dynamic.fake_gps` 配置项模拟位置） |
| 交互 | 随机唤起 activity（默认仅 exported / 带 intent-filter，防误触内部组件）+ monkey 随机点击兜底；权限弹窗由 `install -g` 预授权 + `pm grant` 兜底规避；需登录的样本用 `manual_login: true` 启动后暂停，等操作者手动登录按回车（启动键）继续 |
| 反沙箱 | 不硬刚；探测环境行为（模拟器/反调试/root）本身作为恶意信号上报 |
| 智能终止 | 初始 5 分钟 / 活跃延长至多 15 分钟 / 静默 45 秒提前收网 |
| 同包名预检 | 安装前检测设备是否已有同包名应用：**同版本 → 跳过安装直接测试**；版本不同/未知默认拒绝安装（防误覆盖），`replace_existing: true` 才先卸载（连数据清除）再装；`cleanup_uninstall: false` 测完保留不卸载 |

### 实现说明（v1）

- **流量抓包**：宿主机 HTTP 代理（`proxy_port`）+ 设备全局代理。模拟器自动使用
  `10.0.2.2`；真机需 `dynamic.host_ip` 或自动探测宿主机局域网 IP。HTTP 记录完整
  URL，HTTPS 记录 CONNECT host:port 并透传隧道，不破坏样本网络行为。
  运行前先采集一段**流量基线**（`baseline_seconds`），跑完后差集剔除设备上
  其它应用的"邻居流量"，报告只保留最可能属于样本的端点。
- **Frida**（可选）：`use_frida: true` 时若设备有 frida-server 则 hook：
  `Runtime.exec`（命令执行）、`SmsManager.sendTextMessage`（扣费短信）、
  `DexClassLoader.<init>`（动态加载）、`URL`（网络）、`File.delete` /
  `FileOutputStream`（文件删除/写入）、`SQLiteDatabase.delete` / `execSQL` /
  `ContextWrapper.deleteDatabase`（删库）、`DevicePolicyManager.wipeData` /
  `lockNow`（设备管理器远程擦除/锁定）；无 frida-server / 附加失败一律降级为
  系统层采集，不报错。
- **授权策略**：`install -g` 预授权全部危险权限 + `pm grant` 兜底（等效"弹窗优先
  点允许"），避免交互卡在权限弹窗。
- **activity 唤起**：启动后随机顺序 `am start -n` 唤起可被外部唤起的 activity
  （manifest 中 `exported=true` 或带 intent-filter 且 targetSdk≤30），强制执行
  更多代码路径（恶意行为常藏在非 launcher activity 中）。**排除 launcher
  activity**（MainActivity 已由 launch 打开，重复 `am start` 等于重启整个程序），
  其余 activity 在同一 task 栈内压栈导航（返回键可回退）。默认**不唤起非导出
  （内部）activity**——它们只能被 App 内部调用，强行直启可能触发副作用路径或
  缺参数噪音崩溃；确需全部唤起时设 `interact_hidden_activities: true`。
- **智能终止**：`initial_timeout` 后前台仍活跃则延长至 `max_timeout`；连续
  `idle_timeout` 秒无前台/无流量提前收网。
- **跑后清理**（安全铁律 3）：无论成功/异常，`finally` 必执行卸载样本 + 清除
  设备全局代理；清理失败会在报告标注 `cleanup_ok: false`。若测试设备上已有
  **同包名正式版应用**（同版本直接测试）不想跑完被卸载，可设
  `cleanup_uninstall: false` 保留（报告标注 `kept_installed: true` 审计；
  代理仍无条件清除）。
- **手动登录门**（`manual_login: true`）：部分 App 需要登录才能展现真实行为，
  自动化交互（activity 驱动 / monkey）无法替操作者输入账号密码。启动 App 后
  暂停自动化交互，提示操作者在设备上手动登录，完成后按**回车（启动键）**继续；
  等待超时（`manual_login_wait`，默认 180s）自动继续不挂死（stdin 关闭时同样
  立即继续）。登录耗时**不计入智能终止预算**（交互时钟在登录后重新计时），
  避免把 initial/max_timeout 耗尽压缩自动化窗口；登录期间的代理抓包正常采集
  （登录流量同样计入证据）。报告标注 `manual_login_confirmed`（未启用/已确认/超时）。
  CLI 可用 `--manual-login` 临时开启。
- **同包名预检**：安装前检查设备上是否已存在同包名应用。默认
  `replace_existing: false` 拒绝安装（防误覆盖设备已有应用）；设为 `true` 则先
  卸载（连用户数据一并清除）再安装，保证干净环境。

### ★ 测试设备白名单（安全铁律）

程序绝不会碰你的工作设备：

1. **白名单门槛**：只有 `config.yaml` 的 `test_devices` 中显式列出的设备才会被用于运行样本；
   其他 adb 设备（包括你日常连接的模拟器/真机）一律只读不碰，拒绝一切操作
2. **样本不落地工作设备**：恶意样本只安装到白名单测试设备
3. **跑后清理**：动态分析结束自动卸载样本、清理采集文件

`test_devices` 为空时动态分析永不自动触发（默认安全状态）。

> ⚠️ **显式指定覆盖**：CLI 参数 `--device <serial>`（`analyze` / `dynamic` 子命令）
> 显式指定设备时**绕过白名单门槛**——这是用户明确授权的高风险操作，报告会如实标注
> "绕过白名单"以便审计。`--device` 指定设备不在线时不会静默回退到其他设备。
> 除此以外的任何设备仍受白名单铁律约束。

### 隐私硬约束

**默认禁止上传任何数据。** 动态分析不会上传 APK；威胁情报 / hash 比对默认关闭，
只有你在配置中显式启用并填入 API key 后才会进行外部网络交互。

## 架构 / Architecture

```
apkguard/
├── cli.py              # 命令行入口（analyze / scan / dynamic）
├── config.py           # 配置加载（config.yaml + CLI 覆盖）
├── static/             # 静态分析
│   ├── apk_parser.py   # APK/AAB 双通道解析（androguard；轻量 method_ids，不建 xref 调用图）
│   ├── network_extract.py  # C2 端点提取与特征打分
│   └── detectors/      # 10 个内置检测器（BaseDetector 插件机制 + 注册表，Python 代码）
├── rules/              # YAML 规则库（用户可编辑）
├── engine/             # 规则引擎 / 打分分级 / 数据模型
├── dynamic/            # 动态分析执行体（第二阶段）
│   ├── backend.py          # 可插拔后端抽象 + 执行入口（预检/落盘）
│   ├── device_manager.py   # 测试设备白名单隔离（安全核心）
│   ├── adb_runner.py       # 按 -s serial 限定的 adb 封装（多设备安全）
│   ├── executor.py         # 编排 + 智能终止 + 跑后清理
│   ├── traffic.py          # 代理抓包（HTTP URL / HTTPS CONNECT 端点）
│   ├── frida_collector.py  # 可选 Frida hook（无则降级系统层）
│   ├── interaction.py      # pm grant 预授权 + monkey 交互
│   └── decoy.py            # 诱饵数据（通讯录/短信/通话）
└── output/             # 终端 / JSON / HTML 报告
```

## 技术栈 / Tech Stack

Python 3.10+ · androguard 4.1.4 · PyYAML · pytest

## 开发状态 / Roadmap

- [x] 第一版：静态分析引擎（解析 / 10 检测器 / 规则引擎 / 报告 / 测试）
- [x] 第二阶段：动态分析执行体（adb 后端 + 代理抓包（基线剔除）+ Frida 采集（可选降级，含破坏性操作 hook）+ monkey 交互 + activity 驱动 + 智能终止 + 跑后清理（含 cleanup_uninstall 保留开关））
- [ ] 增强：壳检测（apkid 特征库）、本地 hash 比对、威胁情报查询（默认关闭）
- [ ] AAB Manifest 精确 protobuf 解析（待真实样本验证）
