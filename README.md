# apkguard

Android 恶意行为静态检测工具（APK / AAB）

> ⚠️ 本项目处于第一版开发中（静态分析引擎），文档随开发进度补全。

## 定位

一个 Python CLI 工具，静态分析安卓 APK（及 AAB）文件，检测恶意行为并产出
可分享的多格式报告。规划了混合架构（静态 + 动态沙箱），分阶段落地：
第一版为纯静态分析引擎，第二版实现动态分析（可插拔后端）。

## 特性（第一版）

- 输入：APK（完整支持）、AAB（基础支持，实验性）
- 9 类检测维度：危险权限+敏感 API 调用链、动态代码加载、无障碍滥用、
  悬浮窗/覆盖、短信/通话、隐私数据外传、C2 网络端点分析、签名/证书异常、
  模拟器探测/反沙箱识别
- 多档风险阈值（`--severity low|normal|high`，默认 low 少漏报）
- 输出：终端详情/汇总表、JSON（中英双语标签）、自包含单文件 HTML 报告
- 隐私硬约束：默认禁止上传任何数据，外部交互默认关闭

## 快速开始

```bash
# 虚拟环境
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# 单文件分析
.venv\Scripts\python -m apkguard analyze path/to/app.apk

# 批量扫描
.venv\Scripts\python -m apkguard scan ./apk_folder/
```

## 文档

- 详细使用文档见 `docs/`（随开发补全）
- 配置说明见 `config.yaml`
