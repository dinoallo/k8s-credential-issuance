# ServiceAccount `sa.key` 迁移方案

**状态：** 方案归档，生产实施前仍需完成部署加固

**日期：** 2026-10-29

本文只覆盖 Kubernetes ServiceAccount JWT signing key（通常为
`/etc/kubernetes/pki/sa.key`）从 master 节点迁移到外部 KMS/HSM 的方案。

## 1. 目标与边界

迁移完成后：

- master 节点不再持有可导出的 ServiceAccount JWT 私钥；
- 新 token 仍由原有 `sa.key` 的 key material 签名，只是由外部 KMS 以不可导出方式托管；
- `sa-signer` 只通过受限 KMS API 使用 key，不读取私钥文件；
- 旧 token 和新 token 继续使用同一把公钥验证；
- 原有 `kid`、算法和 issuer 保持不变；
- KMS、authority、signer 或 ledger 不可用时，新签发 fail-closed。

本文不改变 ServiceAccount 的 claims 绑定规则，也不把 authority 的 EAA
Grant signing key 或 worker identity key 当作 `sa.key` 处理。

## 2. 推荐迁移策略

采用“原 key material + KMS import”，不生成新的 signing key，也不把 master
上的旧私钥复制到 signer 或普通文件存储：

```text
旧 token ──┐
           ├── 同一份 sa.pub/JWKS 验证
新 token ──┘

worker/provider
      -> sa-node-agent
      -> sa-authority
      -> sa-signer
      -> external KMS
```

当前仓库不提供通用 key import 命令。必须由目标 KMS 的安全运维流程把现有
`sa.key` 做一次受控导入，并证明导入后的 public key 与原 `sa.pub` 完全一致。

## 3. 迁移前盘点

迁移前需要记录：

1. 当前 `sa.key` 的算法、`kid`、对应 `sa.pub` 和 issuer；
2. kube-apiserver、controller-manager、token webhook、脚本及静态 Pod
   manifest 中所有私钥引用；
3. 当前 token 的最大有效期、verifier cache TTL 和 JWKS 缓存时间；
4. 所有依赖旧公钥验证 ServiceAccount token 的 verifier；
5. 当前 token 请求是由旧 API-server carrier 处理，还是已经走
   `sa-node-agent`/provider；
6. 迁移期间可以接受的 token 签发中断窗口和回滚窗口。

在盘点完成前，不应删除或替换 master 上的旧私钥。

## 4. 导入原有 signing key

不要在本迁移中生成新的 signing key。先解析现有 `sa.key`，计算其 public
key fingerprint，并与 `sa.pub` 和当前 verifier 使用的 JWK 比较。确认一致后，
将同一份 key material 导入 KMS：

```text
purpose    = sa-jwt
algorithm  = 保持现有算法，例如 RS256
key_ref    = kms/sa/imported-existing-key
key_id     = 保持现有 kid
generation = sa-generation-existing
```

KMS policy 至少需要绑定：

- domain 为 `sa`；
- purpose 为 `sa-jwt`；
- 固定且与现有 token 一致的 algorithm 和 `key_id`；
- `operation_id` 幂等和结果恢复；
- signer 的短期身份或 mTLS；
- 签名、禁用、轮换和恢复审计。

导入完成后，KMS 只能返回 public JWK 和签名结果，不能通过 API 返回私钥给
`sa-signer`。`sa-signer` 只能提交已经由公共 core 校验过的 typed claims
signing intent。

如果 KMS 不能保留原有 public key 或 `kid` 语义，则这不是严格的“不轮转”
迁移；应先解决 KMS import/metadata 映射问题，而不是在 signer 中生成另一把 key。
不轮转也意味着继续信任现有 key material；如果该 key 曾经疑似泄露，exact-key
import 不能消除历史暴露风险，此时必须按应急密钥流程处理。

## 5. 配置 generation 和 signer

生产 signer 使用 `kms_endpoint`，并让导入的原 key 成为 active generation：

```json
{
  "kms_endpoint": "https://kms.example",
  "key_generations": [
    {
      "generation": "sa-generation-existing",
      "key_id": "existing-sa-kid",
      "key_ref": "kms/sa/imported-existing-key",
      "algorithm": "RS256",
      "state": "Active"
    }
  ]
}
```

`--allow-local-key-provider` 和 `local_key_files` 只能用于隔离开发测试，
不能作为迁移后的生产回退路径。

Authority 的 workload registration 必须继续使用与现有 token 兼容的 generation
和 `key_id`。这次迁移不引入新的 signing generation。Grant 的 binding、claims
digest、audience、issuer、ServiceAccount UID、Pod UID 和有效期仍由现有 SA
plugin 精确校验。

## 6. 保持原有 token 的验证能力

由于 key material 不变，已经签发的 token 和迁移后新签发的 token 都继续由原有
`sa.pub` 验证。迁移期间必须保持原有 public JWK、`kid`、algorithm 和 issuer
不变。

KMS import 完成并通过签名验证后，旧 token 不需要等待新的 key overlap；但仍需
保留原有 public key discovery，直到所有 verifier 完成切换。

当前 `sa-signer` 的 JWKS endpoint 主要从 KMS provider 发布 key metadata；
KMS import 必须确保该 endpoint 返回与现有 `sa.pub`、`kid` 和 algorithm
一致的 JWK。不能把旧私钥放入 `local_key_files` 作为迁移方案。

## 7. 切换 token 签发路径

切换必须分成“验证 KMS import 签发”和“停止旧签发”两个阶段。

### 阶段 A：验证新路径

- 使用原有 generation 获取一个短 TTL token；
- 检查 JWT header 中的 `kid` 与迁移前完全一致；
- 检查 issuer、audience、subject、ServiceAccount UID 和 Pod UID；
- 使用迁移后的 JWKS 和原 `sa.pub` 验证新旧 token；
- 比较迁移前后的 public key fingerprint、algorithm、issuer 和 `kid`；
- 验证 KMS timeout、重复请求和 signer 重启不会生成不同 token；
- 验证 authority、KMS、ledger 或 audit 故障时不会回退到本地签名。

### 阶段 B：停止旧路径

将实际 TokenRequest 流量切换到经过认证的
`sa-node-agent`/provider -> `sa-authority` -> `sa-signer` 路径，然后确认
旧 API-server signing path 不再产生新 token。

旧 API-server carrier 可以通过显式的 `legacy-token-grant` 模式过渡；这个
模式只兼容 Grant 的传输格式，不代表 `sa.key` 已经导入 KMS，也不能替代
worker identity、attestation 或 KMS 切换。

当前命令中的静态 `bindings` 只适合 bootstrap/test。生产切换前必须使用
基于 attestation 的 resolver，并绑定不可变的 ServiceAccount UID、Pod UID、
audience、issuer 和 generation。

## 8. 从 master 移除旧私钥

只有在以下检查全部通过后，才从 master 节点移除旧 `sa.key`：

- 所有旧 signer 配置和启动参数都已不再引用该文件；
- 新 token 的 `kid`、algorithm、issuer 和 public key fingerprint 与迁移前一致；
- 旧 token 和新 token 均能使用同一份 `sa.pub` 验证；
- 所有需要 token 的组件已经使用新的请求路径；
- KMS、authority、signer、ledger 和 audit 的告警已配置；
- 已完成一次 signer 重启、KMS timeout 和网络恢复测试；
- 已保存迁移审计记录和受控恢复材料。

移除的是 master 上的私钥副本。由于 key material 没有变化，旧公钥继续作为
正常的 verifier/JWKS key 发布；不要因为完成文件迁移而撤销或替换它。

## 9. 迁移后的 key 状态

本方案不退役原有 key。KMS 中导入的 key 继续作为 active signing key：

1. 保持原有 `key_id`、algorithm、issuer 和 public JWK；
2. 仅在 KMS emergency disable 或后续明确的 key rotation 时改变状态；
3. 审计确认 signer 不再读取 master 上的私钥文件；
4. 保留符合组织策略的加密恢复记录，不在普通文件系统中保留可用私钥。

## 10. 当前仓库支持和剩余工作

仓库已经提供：

- `sa-signer` 的外部 HTTP KMS adapter；
- `sa-jwt` purpose、`key_ref`、generation 和 `key_id` policy binding；
- active/renewing/draining generation 状态；
- JWKS 和 key metadata endpoint；
- claims canonicalization、binding 校验、Grant 幂等和结果恢复；
- node-agent/provider 的 direct token 请求路径。

迁移前仍需要完成或由部署系统提供：

- 目标 KMS 的 exact-key import、不可导出和恢复流程；
- 原有 public JWK、`kid` 和 algorithm 的一致性校验；
- kube-apiserver/controller-manager 到新 token 路径的实际切流；
- 生产 attestation resolver、mTLS identity 和 HA ledger；
- master 私钥引用扫描、删除和审计工具；
- 失败注入、token TTL 验证和回滚演练。

因此，本仓库当前是可测试的 SA 参考路径，不应直接视为已完成生产迁移工具。

## 11. 验收标准

迁移可验收的最小条件是：

1. 新 token 由外部 KMS 中导入的原有 key material 签名；
2. `sa-signer` 进程和配置目录中没有可导出的 JWT 私钥；
3. 新 Grant 继续使用约定的 generation/key ID，且没有出现新的 signing key；
4. 迁移前后的 public key fingerprint、algorithm、issuer 和 `kid` 完全一致；
5. 旧 token 和新 token 都能由原有 `sa.pub` 验证；
6. KMS 不可用时不会回退到本地 `sa.key`；
7. master 节点不再有旧 `sa.key`，且启动参数和 manifest 没有残留引用；
8. 重试返回相同的已记录 token 结果，不能重复签出不同 artifact；
9. KMS import 完成验证后，master 节点和启动参数中不再存在旧私钥引用。

## 相关文档

- [ServiceAccount 签发参考部署](../deployment/sa-issuance.zh-CN.md)
- [Credential Issuance Contract v1](../contracts/issuance-v1.zh-CN.md)
