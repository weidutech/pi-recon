<p align="center">
  <img src="assets/pi-recon-banner.svg" alt="PI Recon — lightweight AI red teaming harness for authorized agent challenges" width="100%">
</p>

<h1 align="center">PI Recon</h1>

<p align="center">
  轻量 harness：在授权 Agent 安全挑战里把「拉题 → 侦察 → 校验 → 摘要」跑成闭环。
</p>

<p align="center">
  <em>A thin AI red teaming harness for authorized agent / GenAI security challenges — not a heavy framework.</em>
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Docker ready" src="https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white">
  <img alt="Secret-safe builds" src="https://img.shields.io/badge/build-secrets_not_baked-39D98A">
</p>

PI Recon 源自我们在百度安全挑战赛 / BCTF Agent Plus 攻防赛中的实践。赛程里很清楚的一点是：很多时候，一层足够薄的 harness——调度、超时、提交闸门、把上一轮试过的路径记下来——就能拿到不错的成绩；堆得很重的框架，在真正解题时未必有对应增益。

所以这个仓库刻意保持简单。它更像一套可自托管的 **AI red teaming tools** 雏形：把授权挑战里重复出现的几步串起来（取任务、起实例、有界跑 agent 侦察、校验候选结果、留下摘要），方便改 prompt、改并发、看日志。不是完整平台，也不是通用扫描器。

## 它做了什么

| 能力 | 作用 |
|------|------|
| 持续填槽调度 | 空闲并发槽自动补任务，避免队列尾部长期饿死 |
| 有界执行 | 单题硬超时，结束后释放平台资源 |
| 多阶段侦察 | 同题内续接上下文，少做重复探测 |
| 结果闸门 | 格式校验、去重、连续错误熔断 |
| 结构化摘要 | 技术栈、攻击面、已试路径、近失点、下一步建议 |
| 安全构建 | 日志、会话、密钥不进 Git，也不写进 Docker 镜像 |

## 工作流程

```mermaid
flowchart LR
    A[获取任务] --> B[启动目标实例]
    B --> C[并行侦察会话]
    C --> D{候选结果校验}
    D -->|有效| E[提交并记录]
    D -->|未完成| F[生成侦察摘要]
    E --> G[释放资源]
    F --> G
    G --> H{仍需继续?}
    H -->|是| B
    H -->|否| I[结束任务]
```

## 快速开始

要求 Python 3.10+，并确保 `pi` 命令在 `PATH` 中可用。

```bash
git clone https://github.com/weidutech/pi-recon.git
cd pi-recon

cp .env.example .env
# 在 .env 中填写 BENCHMARK_BASE_URL、BENCHMARK_TOKEN 和 PI_RECON_LLM_KEY

set -a
source .env
set +a

python3 harvest.py --only a-05  # 运行单个任务
python3 harvest.py              # 运行完整任务队列
```

## 项目结构

```text
harvest.py                 主调度器
platform_io.py             挑战平台 API 适配
agent_exec.py              侦察会话执行与事件记录
loot_gate.py               候选结果校验与提交控制
net_llm.py                 LLM 路由与连通性检测
prompts/                   侦察提示词与方法规范
docker/                    容器构建与启动配置
scripts/watch_run_logs.py  运行状态查看工具
```

运行产生的 `jobs/`、`logs/`、`work/` 和 `dist/` 均为本地数据，不会提交到 Git，也不会复制进 Docker 镜像。

## Docker

构建过程不会接收或保存 API key。密钥仅在容器启动时通过环境变量注入。

```bash
MODE=tsec ./docker/build-baidu.sh
docker run --rm --env-file .env pi-recon:tsec
```

使用 `MODE=baidu` 可构建采用 Baidu AWD 网关配置的镜像。

## 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `BENCHMARK_BASE_URL` | 无 | 挑战平台 API 地址 |
| `BENCHMARK_TOKEN` | 无 | 挑战平台访问令牌 |
| `PI_RECON_LLM_KEY` | 无 | LLM API key |
| `PI_RECON_LLM_BASE` | `https://api.deepseek.com/v1` | OpenAI 兼容 API 地址 |
| `PI_RECON_LLM_PROVIDER` | `deepseek` | Provider 名称 |
| `PI_RECON_LLM_MODEL` | `deepseek-v4-flash` | 模型名称 |
| `PI_RECON_CONCURRENCY` | `3` | 并行任务数 |
| `PI_RECON_JOB_TIMEOUT_SEC` | `1200` | 单任务超时秒数 |
| `PI_RECON_SEGMENTS` | `2` | 每个任务的会话阶段数 |
| `PI_RECON_JOBS_DIR` | `jobs` | 本地运行数据目录 |
| `PI_RECON_HINT_AFTER_FAIL` | `1` | 阶段失败后是否获取平台提示 |
| `PI_RECON_SECOND_WAVE` | `1` | 是否重试首轮未完成任务 |
| `PI_RECON_SUBMIT_MAX_WRONG` | `3` | 连续错误提交熔断阈值 |

提示接口可能影响挑战得分；不需要时请设置 `PI_RECON_HINT_AFTER_FAIL=0`。

## 安全边界

PI Recon 只应用于你拥有明确授权的目标。不要用它扫描无关网络、执行拒绝服务攻击或访问未授权系统。

- 不要提交 `.env`、日志、会话、结果归档或私钥文件。
- 构建镜像时不要传入密钥；在运行时使用 `--env-file` 或密钥管理服务。
- 若密钥曾进入公开仓库、构建日志或已分发镜像，应立即撤销并重新签发。
