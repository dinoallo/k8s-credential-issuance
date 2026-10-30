# ServiceAccount `sa.key` 迁移与轮转 Runbook

**状态：** 迁移设计与 Runbook；本仓库尚未实现生产切换

**日期：** 2026-10-30

本文说明 Kubernetes ServiceAccount JWT signing key（通常为
`/etc/kubernetes/pki/sa.key`）与外部 `sa-signer`、KMS 之间的关系。

这里需要区分三种不同的部署目标：

1. **Exact-key 迁移：** 将现有 key material 迁移到外部 KMS，不改变 token 的信任关系；
2. **密钥轮转：** 生成新 key，并更新所有需要信任它的 verifier 和 issuer；
3. **独立签发：** 由 `sa-signer` 使用独立的 issuer 和 verifier/JWKS 通道签发 JWT。这是当前 Helm Chart 部署的参考路径，但不会自动替代 kube-apiserver 原生的 TokenRequest signer。

仅返回 Kubernetes 形状的 `status.token`，或提供 signer 的
`/jwks.json` endpoint，并不能让 kube-apiserver 自动信任该 signer。issuer、audience、claims、公钥信任和 TokenRequest 接入都必须匹配。

## 1. 目标状态与密钥隔离

Exact-key 迁移的目标状态是：

- 外部 KMS 以不可导出的方式保存与旧 `sa.key` 相同的 ServiceAccount JWT key material；
- JWT `kid`、算法、issuer、audience 规则和公钥保持不变；
- `sa-signer` 只通过受限 KMS 签名 API 使用密钥；
- 旧 token 和新签发的 token 继续由同一份公钥验证；
- authority 的 EAA Grant signing key、worker identity key 与 ServiceAccount JWT key 保持分离；
- KMS、authority、signer、ledger 或 audit 故障时，新签发 fail-closed。

以下密钥不能混用：

| 密钥 | 用途 |
| --- | --- |
| Kubernetes `sa.key` / 外部 KMS 中的等价 key | ServiceAccount JWT 签名 |
| `authority.signingKey` | `sa-authority` 签发 EAA Grant |
| node-agent identity key | worker identity proof |
| Infisical bearer token | 访问 Infisical KMS API 的运行时凭据 |

如果 external signer 使用新生成的 KMS key，这就是密钥轮转，不是 exact-key 迁移。如果 consumer 被有意配置为信任独立的 issuance issuer 和 JWKS，则这是独立签发，也不是保持集群原生 `sa.key` 信任关系的迁移。

## 2. 选择迁移策略

### 2.1 不轮转的 exact-key 迁移

只有目标 KMS 支持受控私钥导入，并且能够证明导入后的公钥与现有公钥逐字节等价时，才能使用此策略。KMS 内部 ID 可以变化，但 JWT metadata 必须兼容：

```text
KMS key id（`key_ref`） = 目标 KMS resource ID 或 UUID
JWT `kid`（`key_id`）   = 现有 token header 中的 kid
public_key              = 与旧 sa.key 对应的公钥
generation              = 稳定的 issuance metadata 名称
```

仓库没有提供通用 key-import 命令。Infisical client 可以 list、create、inspect、读取公钥材料和 sign，但部署 Chart 不会导入现有私钥。因此 KMS import 必须由 Helm 之外的受控 provisioning 流程完成。如果目标 KMS 不支持导入现有 key，则不能使用此策略；不能悄悄生成替代 key 后仍称为迁移。

### 2.2 协调式密钥轮转

当旧 key 无法导入、疑似泄露，或明确需要新的密码学身份时，使用此策略。轮转会改变公钥，通常也会改变 JWT `kid` 和 generation。签发第一个新 token 前，所有 verifier 必须已经信任新公钥。

在所有旧 token 以及 verifier/JWKS cache 过期前，旧 key 必须保留用于验证。在本仓库中，旧 generation 可以保持为 `Draining`，新 generation 是唯一的 `Active` generation；`sa-signer` 启动时要求恰好一个 `Active` generation。

### 2.3 独立的 issuance JWT

如果 token 是给外部 workload API 使用，而不是给 kube-apiserver 做原生认证，则可以使用新的不可导出 Infisical KMS key。需要把该 issuer 和 JWKS 配置给 consumer。不要把这种方式描述为保持集群原生 `sa.key` 信任关系。

## 3. 迁移前盘点

在修改任何 key 或请求路径前，记录：

1. 当前 `sa.key` 的算法、JWT `kid`、匹配的公钥、issuer 和期望的 audience；
2. kube-apiserver 的 `--service-account-issuer`、`--api-audiences`、`--service-account-key-file` 和 `--service-account-signing-key-file` 设置，以及对应 Kubernetes 版本的行为；
3. kube-apiserver、controller-manager、token webhook、脚本和静态 Pod manifest 中所有私钥引用；
4. token 最大有效期、verifier cache TTL 和 JWKS cache 时长；
5. 所有依赖旧公钥验证 token 的 verifier，包括它们读取 kube-apiserver 配置还是 `sa-signer` JWKS endpoint；
6. 当前 TokenRequest 走 kube-apiserver 原生路径，还是走 `sa-node-agent`/provider 路径；
7. 每个业务集群是否拥有不同的 issuer 或 ServiceAccount key；
8. 可接受的签发中断窗口和回滚窗口。

在盘点完成、信任关系更新且回滚方案就绪前，不要删除或替换 master 上的旧私钥。

## 4. 为 exact-key 迁移导入现有 signing key

本迁移不要生成新的 signing key。在受控 provisioning 环境中，将现有
`sa.key` 派生出的公钥与 `sa.pub` 及当前 verifier 使用的 JWK 比较。私钥处理必须留在 KMS 批准的 import ceremony 内；不要将私钥复制到 signer Pod、Helm values 或普通共享文件系统。

导入的 KMS key 至少应满足：

- domain：`sa`；
- purpose：`sa-jwt` / `sign-verify`；
- 算法与现有 key 兼容，例如 `RS256`；
- 私钥材料不可导出；
- signer identity 或 mTLS 只允许访问该 key 和 purpose；
- 支持 operation-ID 幂等或持久化结果恢复；
- 对 import、sign、disable、recovery 和后续 rotation 保留审计记录。

导入完成后，`key_ref` 是 KMS key 的 ID 或 UUID。它不是 JWT `kid`，也不是 Infisical bearer token。JWT `key_id` 仍然应保持现有 header `kid`。如果运行时凭据只有 Infisical `Cryptographic Operator` 权限，则必须把 KMS `public-key` endpoint 返回的匹配公钥材料以 PEM 或 base64 编码 DER 填到 `public_key`。

KMS 运行时 API 绝不能返回私钥。如果导入后的公钥或 JWT `kid` 无法保持，必须停止 exact-key 方案并改走协调式轮转。如果旧 key 可能已经泄露，exact-key import 不能消除历史暴露风险，必须走应急密钥流程。

## 5. 配置 `sa-signer` 和 authority

Signer 配置必须包含恰好一个 `Active` generation。下面只是字段形状，不是可直接用于生产的值：

```yaml
signer:
  config:
    cluster_id: workload-cluster-1
    issuer: <与 kube-apiserver 完全一致的 service-account-issuer>
    key_generations:
      - generation: sa-generation-existing
        key_id: <existing-jwt-kid>
        key_ref: <target-kms-key-id-or-uuid>
        public_key: <matching-public-key-pem-or-base64-der>
        algorithm: RS256
        state: Active
  kms:
    provider: infisical
    endpoint: https://infisical.example
    authToken:
      secretName: sa-signer-kms
```

`key_ref` 是目标 KMS resource ID，不能填写 Kubernetes Secret 名称
`kci-issuance-...-signer-kms`。这个 Secret 只存放 Infisical bearer token。
`eaa_keys` 仍然是 authority 的 Ed25519 公钥信任集合，与 ServiceAccount
signing key 无关。

Authority registration 必须使用 token consumer 期望的相同 cluster、issuer、generation、key ID 和 allowed audiences：

```yaml
authority:
  config:
    cluster_id: workload-cluster-1
    issuer: <与 kube-apiserver 完全一致的 service-account-issuer>
    registrations:
      - token_generation: sa-generation-existing
        key_id: <existing-jwt-kid>
        allowed_audiences:
          - <cluster-service-account-audience>
```

当前 `sa-signer` 进程和 Helm Chart 每个 release 只支持一个配置好的
`cluster_id`、issuer 和 active generation。一个独立 issuance 集群不能用同一份 signer 配置服务多个拥有不同原生 ServiceAccount key 或 issuer 的业务集群。应为每个业务集群使用隔离的 release，或重新设计 signer/authority 的配置边界。

参考 Chart 会在受控部署中从 Kubernetes Secret 挂载 KMS bearer token。生产环境应使用平台批准的 workload identity 或 external-secret 注入方式，不能把 KMS management credential 或私钥材料放进 Helm values 或普通 Kubernetes 对象。

## 6. 建立 Kubernetes 原生信任和请求路径

当前仓库提供 node-agent/provider 路径，可以返回 Kubernetes 形状的 TokenRequest response，也提供 signer JWKS endpoint。但它不会配置 kube-apiserver 将原生 ServiceAccount TokenRequest 签名委托给 `sa-signer`，不会安装 kubelet TokenRequest provider，也不会更新 API server 的 trust flags。

在宣称完成 Kubernetes 原生切换前，部署系统必须提供并端到端验证：

1. kube-apiserver 或相关 token verifier 信任与 signer KMS key 对应的公钥；
2. 生成的 `iss`、`aud`、`sub`、`exp`、`iat`、`nbf` 和 `kubernetes.io` claims 符合集群原生 ServiceAccount token contract；
3. TokenRequest 流量实际经过认证的
   `sa-node-agent`/provider -> `sa-authority` -> `sa-signer` 路径；
4. verifier 能通过配置好的 trust bundle 或 JWKS 通道发现 key；单独存在的
   `/jwks.json` 不会自动更新 kube-apiserver 的信任配置；
5. 只有 replacement path 验证通过且具备回滚能力后，才能关闭旧的 API-server signing path。

如果 kube-apiserver 仍然使用旧 `sa.key` 签发原生 TokenRequest，就必须保留该 key 及其配置。在 API server 旁边部署 external signer，并不会自动使删除 `sa.key` 变得安全。

## 7. 协调式密钥轮转流程

如果实际执行的是密钥轮转，而不是 exact-key 迁移：

1. 生成一把批准算法和 `sign-verify` purpose 的新的不可导出 KMS key；
2. 为新 key 分配新的稳定 `generation` 和 JWT `key_id`，记录新公钥；
3. 将新 generation 配置为 `Active`，需要发布或验证旧 token 时将旧 generation 保持为 `Draining`。不能配置两个 `Active` generation；
4. 在签发新 token 前，更新所有 verifier、API-server trust bundle 和 JWKS consumer，使其信任新公钥；在 overlap 窗口内保留旧公钥；
5. 将 authority registration 和 workload binding 更新到新的 generation、key ID、issuer 和 audience policy；
6. 签发短 TTL 测试 token，使用新公钥校验完整 claims、signature、`kid`、issuer、audience 和 binding；
7. 等待至少旧 token 最大有效期，加上 verifier/JWKS cache 和传播窗口；
8. 只有在不再需要验证旧 token 且回滚窗口关闭后，才能 retire 或 emergency-disable 旧 generation。

只修改 `key_ref` 而不更新旧 public key、`key_id` 或 verifier trust 配置，不是有效的轮转。只修改 public key 但 KMS resource 或算法不匹配，也不是有效部署。

## 8. 验证和切换

### Exact-key 迁移验证

- 比较 import 前后的公钥 fingerprint；
- 确认 `key_id`、算法、issuer 和预期 audience 未变化；
- 通过新路径签发短 TTL token；
- 使用原公钥和配置好的 JWKS 验证旧 token 和新 token；
- 确认 signer header 使用原有 `kid`；
- 验证 KMS timeout、authority 故障、ledger 故障和 signer 重启不会触发本地 key fallback；
- 验证重试返回同一份已记录的 token 结果。

### 原生路径切换验证

- 明确测试期间每个 TokenRequest 实际由哪个组件签发；
- 确认 kube-apiserver 接受新路径签发的 token，并拒绝 issuer、audience 或 binding 错误的 token；
- 确认旧路径仍可用于回滚；
- 最后再将生产流量切换到新路径。

旧的 `legacy-token-grant` 模式可以在应用迁移期间保持旧 Grant transport 格式兼容，但它不会导入 `sa.key`、替代 worker identity 或 attestation，也不会配置 kube-apiserver trust。

静态 `bindings` map 只适用于 bootstrap 和测试。生产环境必须使用带签名的 remote-attestation resolver，并由 attestor 返回不可变的 ServiceAccount UID、Pod UID、audience、issuer 和 generation binding。

## 9. 删除旧私钥

只有在以下条件全部满足后，才可以从 master 节点删除旧 `sa.key`：

- 原生 API-server signing path 不再需要该私钥；
- replacement TokenRequest path 已部署并完成回滚测试；
- 旧、新 token 的验证行为已经明确且有监控；
- 新 token 使用批准的 KMS key，任何 signer 进程都不读取私钥文件；
- KMS、authority、signer、ledger、audit 和 trust-discovery 告警已启用；
- recovery material 已按安全策略保存。

如果 kube-apiserver 仍负责原生 ServiceAccount TokenRequest 签名，不要仅因为部署了 `sa-signer` 就删除它的 signing key。当前 Helm Chart 无法独立完成这次 ownership handoff。

## 10. 迁移后的 key 状态

对于 exact-key 迁移，导入 KMS 的 key 继续 active，并保留现有公钥身份。这是托管位置变化，不是密码学轮转。

对于密钥轮转，旧 generation 要保持批准的 overlap 状态，直到 token 有效期和 cache 窗口结束，然后再 retire。新 generation 的 `key_id`、公钥、issuer 和算法成为 active trust identity。

## 11. 仓库支持和限制

仓库已经提供：

- `sa-jwt` KMS purpose，以及 `key_ref`、generation、algorithm 和 `key_id` policy binding；
- active、renewing、draining、retired 和 emergency-disabled generation 状态；
- 通过配置的 KMS adapter 执行受限 JWT 签名；
- JWKS 和 key-metadata endpoint；
- claims canonicalization、binding 校验、Grant 幂等和结果恢复；
- 通过 node-agent/provider 的 direct token request 路径；
- 用于分别部署 authority、signer 和 node-agent 的参考 Helm Chart。

仓库没有提供：

- 将现有 `sa.key` 安全导入 Infisical 或其他 KMS 的功能；
- 自动配置 kube-apiserver issuer、audience、trust bundle 或 signing key；
- 生产级 kubelet TokenRequest provider 安装；
- HA ledger、生产 attestor、完整 mTLS identity provisioning 或生产级 KMS recovery automation；
- 让同一个 signer release 安全服务多个原生集群 key/issuer 对的能力。

Chart 挂载 token Secret 和文件型 store 都是参考部署机制，不能单独满足生产级控制面密钥删除或 credential injection 策略。

## 12. 验收标准

### Exact-key 迁移

1. 新 token 由外部 KMS 中保存的原有 key material 签名；
2. import 前后的公钥 fingerprint、算法、issuer、audience policy 和 `kid` 完全一致；
3. `sa-signer` 不包含可导出的 JWT 私钥，也不会回退到本地 `sa.key`；
4. 旧 token 和新 token 都能由原有公钥验证；
5. 实际 TokenRequest 路径和 verifier trust 已完成端到端测试；
6. 只有在原生 API-server path 不再需要旧私钥后，才能删除 master 节点上的私钥。

### 协调式轮转

1. 新 token 使用新的 KMS key 和 generation；
2. 开始签发前所有 verifier 已信任新公钥；
3. 旧 key 在批准的 overlap 窗口内保持可用；
4. 旧 token 在有效期和 cache 窗口内继续可验证；
5. 只有在回滚关闭且审计证据完整后，才能 retire 旧 generation。

## 相关文档

- [ServiceAccount 签发参考部署](../deployment/sa-issuance.zh-CN.md)
- [Helm 部署](../deployment/helm.zh-CN.md)
- [Credential Issuance Contract v1](../contracts/issuance-v1.zh-CN.md)
