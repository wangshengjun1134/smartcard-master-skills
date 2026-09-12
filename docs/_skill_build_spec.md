# SmartCard Skills 构建规范（所有技能通用）

## 目标
在 `D:\softdata\workspaces\buff\smartcard-master-skills\` 下实现 11 个独立的 TypeScript 技能模块。
**先不用实现 sc-asn1。**

## 0. 独立性（硬性要求）
每个 `sc-*` 目录是一个**完全自包含**的模块：
- 只允许依赖 `node:` 内置模块 + 自身目录内的相对导入。
- **禁止** import 其他 `sc-*` 目录的任何文件，禁止跨技能共享代码。
- 允许在不同技能间**复制**小段必需代码（如 SM3/SM4/padding/hex 工具），这是刻意为之。
- 用户可能只安装其中某几个技能，所以每个目录必须能单独拷走并运行。

## 1. 运行环境
- Node 可执行文件（必须用绝对路径）：`C:\Users\DELL\.workbuddy\binaries\node\versions\22.22.2-2\node.exe`
- Node 22.22.2 **原生支持 TS 类型剥离**，无需 tsc / tsx / ts-node，无需任何 npm 依赖。
- 因此 TS 代码**只能使用可擦除语法**：
  - 允许：`interface`、`type`、`as`、`: 类型注解`、泛型、`import type`、`export type`、可选参数 `?`
  - **禁止**：`enum`、`namespace`、装饰器、`private/public` 参数属性（constructor(private x: string)）、`declare` 以外的高级特性
  - 想表达常量枚举请改用 `const X = {...} as const` + `type X = typeof X[keyof typeof X]`
- 每个技能目录放 `package.json`：`{"name":"sc-xxx","private":true,"type":"module","version":"1.0.0"}`
  （`"type":"module"` 必需，否则 ESM import 不可用）
- 相对导入**必须带 `.ts` 后缀**：`import { foo } from "../algorithms/foo.ts";`
- 加密原语优先用 `node:crypto`。国密 SM2/SM3/SM4 Node 不提供，用纯 TS + BigInt 自实现，并**用官方测试向量验证**。

## 2. 目录结构（每个技能严格一致）
```
sc-xxx/
├── SKILL.md              # 给 Agent 加载，极简
├── schema.json           # 输入输出契约（JSON Schema draft 2020-12）
├── package.json
├── scripts/
│   └── xxx.ts            # 唯一可执行入口
├── algorithms/
│   ├── a.ts
│   └── b.ts              # 按算法拆分，一个文件一个算法族
├── tests/
│   ├── vectors/
│   │   └── *.json        # 标准测试向量
│   └── xxx.test.ts       # node --test 用例
└── README.md             # 开发者文档，不给 Agent 加载
```

## 3. CLI 契约（scripts/xxx.ts）
支持三种输入方式，只输出一份 JSON 到 stdout，**stdout 必须只有 JSON，不能有任何日志**：
```bash
node scripts/xxx.ts --input '{"operation":"...","algorithm":"..."}'
node scripts/xxx.ts --input-file ./in.json
echo '{"operation":"..."}' | node scripts/xxx.ts
```
- 成功：`{"ok":true, ...业务字段}`，退出码 0
- 失败：`{"ok":false,"error":{"code":"...","message":"..."}}`，退出码 1，**不抛未捕获异常**
- error.code 用 SCREAMING_SNAKE_CASE，如 `UNSUPPORTED_ALGORITHM` / `MISSING_PARAMETER` / `INVALID_KEY_LENGTH` / `INVALID_HEX` / `VERIFY_FAILED` / `MALFORMED_INPUT`

## 4. 数据表示规则
- 所有二进制输入/输出一律 **HEX 字符串，大写，无 0x 前缀，无空格**。
- 未指定的密码参数**不得猜测**，必须报错（如未给 IV 就报错，不要默认全 0）。
- 密钥、敏感中间值**绝不打印/写入日志/回显**。错误 message 中不得包含密钥内容。
- 必须保留前导零字节（如 4 字节整数 0x00000001 输出 `00000001`）。

## 5. SKILL.md 规范（极简，英文正文，只保留这些段落）
```markdown
# sc-xxx

<一句话 Purpose>

## Operations

`op1`
`op2`

## Algorithms

`ALGO-1`
`ALGO-2`

## Input

| Field | Type | Required | Description |
|---|---|---|---|
| operation | string | yes | ... |
| algorithm | string | yes | ... |
| key | hex | yes | ... |
| data | hex | yes | ... |

## Output

```json
{
  "ok": true,
  "result": "HEX"
}
```

## Rules

- Binary input/output: HEX (uppercase).
- Never log keys.
- Do not infer missing cryptographic parameters.
```
不要写实现细节、不要写测试向量、不要写长篇说明。SKILL.md 控制在 60 行以内。

## 6. schema.json
JSON Schema draft 2020-12，描述输入对象：`$schema`、`$id`、`type:object`、`required`、`properties`（含 type/描述/pattern 如 hex 的 `^([0-9A-Fa-f]{2})*$`）、`additionalProperties:false`，用 `oneOf`/`if-then` 表达条件必填（如 AEAD 需要 iv/aad）。

## 7. README.md
开发者文档，中文，包含：安装与运行、完整参数表、算法清单与说明、示例命令、测试向量来源、安全注意事项、已知限制。

## 8. 测试要求（必须真正跑通）
- 用 `node:test` + `node:assert`。
- 运行：`node.exe --test tests/` （在该技能目录下执行，注意 --test 后接目录或文件）
- **至少覆盖**：每个算法一条 known-answer 测试向量（NIST/RFC/GM-T 官方向量）；必填参数缺失报错；非法 hex 报错；错误密钥长度报错。
- 测试向量放 `tests/vectors/*.json`，测试代码读取它们，不要硬编码在测试里。
- 交付前**必须实际执行命令跑一遍，确保 pass 0 fail**，并在最终汇报里贴出测试摘要。

## 9. 交付前自检清单
1. `node scripts/xxx.ts --input '...'` 各 operation 均能跑通并输出 JSON
2. `node --test tests/` 全部通过
3. 目录内无任何跨技能 import（grep 一下 `sc-` 开头的相对路径 `..`）
4. SKILL.md 符合第 5 节格式且 < 60 行
5. README.md 存在且为中文

## 10. 汇报
完成后用 200 字以内汇报：实现了哪些算法、测试通过数量、遇到的问题与取舍。不要粘贴大段代码。
