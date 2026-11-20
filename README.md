# cache-poisoning-detector

TypeScript 编写的 Web 缓存投毒检测工具：自动找出**影响响应内容却不在缓存键里**的请求输入，并在**不污染真实用户缓存**的前提下验证投毒是否成立。附带一个"缓存代理 + 源站"演示环境，内置多种不同成因的投毒点用于检验检测器。

## 快速开始

```bash
npm install
npm run demo        # 终端 1：启动演示环境 (cache :8080 -> origin :4000)
npm run scan -- --target http://127.0.0.1:8080 \
  --paths /index.html,/search.html,/redirect.html,/api/data.json,/static/app.js \
  --report report.json
```

找到已验证投毒向量时退出码为 1（便于接入 CI)。Node ≥ 22.6 可直接运行 .ts，无需构建。

## 检测方法

### 1. 安全隔离（核心约束：不弄脏线上缓存）

每个可能写缓存的探测请求都携带随机 cache-buster 参数 `__cpb=<rand>`。预检阶段会先证实：

- 目标路径确实会被缓存（同一请求第二次返回 `X-Cache: HIT`);
- **buster 参数本身在缓存键里**（换 buster 值必为 MISS)。

两条都满足才继续——否则跳过该路径并说明原因。这样所有"投毒"只发生在真实用户永远不会命中的独立键空间里。验证逻辑（`src/verify.ts`）证明的是：**两个仅在可疑输入上不同的请求映射到同一缓存条目，且后到的"受害者"请求拿到了先到的"攻击者"内容**。扫描末尾还有安全审计：请求干净 URL，断言其中不含任何 canary。

### 2. 噪声免疫的响应比对

响应里天然有时间戳、request-id 等随机内容。`src/diff.ts` 先归一化易变模式（ISO 时间戳、UUID、epoch 毫秒、长 hex token）和我们自己注入的 buster 值，再从 3 份基线学习稳定行集合；探测响应只有出现**基线中从未见过的行**（或丢失稳定行）才算有差异，且每个探针发两次、差异可复现才采纳。

### 3. 输入影响探测 → 键成员判定

- 头部探针：`X-Forwarded-Host`、`X-Original-URL`、`Referer`、`Host` 等（`src/probes.ts`);
- 参数探针：`q`、`next`、`utm_*`、`callback` 等常见名；
- 对确认影响响应的参数再做变换：**大小写**(`Next`)、**百分号编码名**(`%6eext`)、**重复参数**(`?q=A&q=B`，缓存取第一个、后端可能取最后一个）。

每个"影响响应"的输入都要过键成员判定：同 buster 下改变该输入，若第二个请求 HIT 且拿到第一个请求的内容 → 输入不在键里，投毒确认（HIGH)；若 MISS → 输入在键里，不可利用（info)。

## 演示环境内置的投毒点（不同成因）

| # | 位置 | 成因 | 检测结果 |
|---|------|------|----------|
| V1 | `/index.html` canonical 链接 | `X-Forwarded-Host` 未入键 | HIGH |
| V2 | `/index.html` referrer 文案 | 缓存忽略列表 `utm_*`，后端却反射 | HIGH（含编码名变体 `%75tm_source`) |
| V3 | `/search.html?q=` | 重复参数：缓存键取第一个、后端用最后一个 | HIGH |
| V4 | `/index.html` 资源 URL | 缓存键对 Host 去端口，后端反射原始 Host | HIGH |
| C1 | `/redirect.html?next=` | 反射但**在键里** → info，不误报 | info |
| C2 | `/api/data.json` | `Cache-Control: no-store` → 不适用 | 跳过 |
| C3 | `/static/app.js` | 纯静态，无反射 | 干净 |

缓存规则本身也是演示的一部分（`demo/cache.ts`)：按路径后缀（`.html/.js/.css`）和响应头（`Set-Cookie`、`Cache-Control`）决定是否缓存，TTL 60s，返回 `X-Cache`/`Age`。

## 局限

- 依赖前端层暴露 `X-Cache`/`Age` 之类的命中信号；没有时跳过并提示（可扩展为计时/内容启发式）。
- 行级 diff 假设反射点与易变内容不同行；对单行内混排的场景可能漏报。
- 只测 GET；fat-GET（带 body 的 GET）等更偏门的向量未覆盖。
