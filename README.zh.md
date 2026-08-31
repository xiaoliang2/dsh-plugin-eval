# dsh-plugin-eval（插件安装前综合评估）

面向 DeepSeek Harness（DSH）插件的**安装前综合评估**工具——供应链安全检查门，思路对标 `npm audit` + Lighthouse。它从安全、兼容、体积/性能、社区信号、文档五个维度给插件打分，并输出 **0–100 可靠性总分**、字母等级和安装结论（recommended / acceptable / caution / blocked）。

> **只做静态分析。** 引擎绝不执行目标插件的代码——本地通过 `fs` 服务读文件，社区元数据通过可选的 `web` 服务读公开的 GitHub/npm 数据。评估一个恶意插件不会在你的机器上运行任何东西。

## 功能

注册一个模型工具 `plugin_eval`，可在对话中直接调用：

```
plugin_eval(target: <本地路径 | owner/repo | npm 包名>)
```

| 维度 | 权重 | 测量内容 |
| --- | --- | --- |
| 安全 | 40% | 密钥材料（私钥、AWS/GitHub/npm/Slack token、JWT 等）、危险代码模式（`eval`、`child_process`、`vm`、动态 require、明文 HTTP 端点）、**OSV 数据库已知漏洞查询（npm audit 式）**、依赖锁定、生命周期脚本（`postinstall` 等）、manifest 卫生 |
| 兼容性 | 25% | `engines.node` 与运行时、**DSH `peerDependencies` 与检测到的 DSH 版本**、依赖锁定比例、manifest 身份 |
| 体积/性能 | 15% | 文件数、有效源码体积、源码/依赖占比、是否有测试与文档（Lighthouse 式静态基准，不执行计时） |
| 社区 | 10% | GitHub stars/forks/活跃度/是否归档、npm 下载量/版本数/最近发布（可选联网；离线时跳过并重新归一化） |
| 文档与质量 | 10% | README、LICENSE、测试、示例、changelog、contributing |

另含**锁文件审计**（package-lock.json / pnpm-lock.yaml / yarn.lock）：缺失锁文件降低可复现性，锁文件中记录的每个固定解析也会一并喂给 OSV 查询。

缺失的维度会被**剔除并重新归一化权重**（与 Lighthouse 一致），因此离线也能得到总分。

结论以安全为主导（类似 `npm audit`）：安全分低于 40 时即使其他全绿也强制 `blocked`。

## 安装

本包是标准 DSH 插件：入口 `lib/index.js` 已提交、无需构建，且声明 `dsh.bundle.patch` → `./cordis.patch.yml`，可从 git 或 npm 安装并作为 Cordis 行挂载：

```bash
dsh plugin add <本仓库或包名>
```

仅依赖 Host 提供的 `@deepseek-ai/dsh-tools`（peer），并按需使用 `fs` / `web` 服务。

## 使用

从模型侧指向**本地检出**可获得最深扫描：

```
plugin_eval(target: "/path/to/plugin-checkout")
plugin_eval(target: "owner/repo")          # 远程深扫（git tree + raw 文本，不 clone、不执行）
plugin_eval(target: "some-npm-package")    # 仅 manifest + 社区
```

当目标是 GitHub `owner/repo` 且联网开启时，会通过 `web` 服务远程深扫仓库
（git 文件树 + raw 文本），而不是只停在与数据。可选 `dsh_version` 参数可覆盖
自动检测的 DSH 版本，用于 `peerDependencies` 校验。

输出示例：

```jsonc
{
  "target": "/path/to/plugin",
  "composite": { "score": 90.1, "grade": "A", "verdict": "recommended" },
  "report": "# Plugin Reliability Report — …\n## Composite: **90.1/100 (A)** …"
}
```

## 开发

```bash
node test/util.test.mjs       # semver 与依赖锁定辅助
node test/engine.test.mjs     # 完整流水线（基于夹具，离线）
node test/community.test.mjs  # 使用 mock 网络服务的社区聚合
node test/advanced.test.mjs   # OSV 查询、锁文件审计、远程深扫、DSH 版本检测
```

（`node --test` 会为每个文件启动子进程；若沙箱阻止，请直接运行单文件。）

## 目录结构

```
lib/
  index.js          Cordis 插件入口（注册 plugin_eval）
  engine/
    index.js        evaluatePlugin() 编排器 + 报告渲染
    util.js         semver / 锁定判断 / 本地源码采集
    security.js     密钥与危险模式扫描、manifest 审计
    performance.js  体积基准
    community.js    GitHub/npm 聚合（可选 web）
    compatibility.js 版本兼容检查
    score.js        综合评分、等级、结论
    vulns.js        OSV 已知漏洞查询（npm audit 式）
    lockfile.js     package-lock / pnpm / yarn 锁文件审计
    remote.js       远程 GitHub 深扫（文件树 + raw 文本，不 clone）
    runtime.js      DSH 版本检测（用于 peer 校验）
test/               node:test 套件 + 夹具（good vs risky）
cordis.patch.yml    包补丁（dsh.bundle.patch 目标）
```

## 安全模型

- 绝不执行目标插件代码。
- 有界读取（文件数/字节数上限）、目录深度受限。
- 联网仅拉取公开元数据，所有请求限时。
- 结果均为自有 JSON；从不序列化 DSH 实时对象。

## License

MIT
