# ServiceAccount 签发参考部署

本仓库实现的是冻结的 `issuance/v1` 契约下的 SA 参考路径，可用于本地集成和安全契约测试。文件存储和静态 node-agent resolver 不是 HA 生产部署。

## 进程与信任边界

```text
sa-node-agent --（worker proof）--> sa-authority --（Grant adapter）--> sa-signer
       |                                                               |
       +-- 本地 Unix socket / TokenProvider API                          +-- 受限 KMS
```

构建三个独立部署的进程：

```bash
go build ./cmd/sa-authority ./cmd/sa-signer ./cmd/sa-node-agent
```

Authority 持有 EAA 私钥和 registration/Grant ledger；signer 只接收配置的 EAA 公钥和 KMS adapter；node-agent 持有 worker identity key，不能持有 Kubernetes 管理员凭据。

## 配置要点

所有相对路径都相对于配置文件解析。下面只展示字段形状，`REPLACE_*` 不是可用的真实密钥。

Authority 至少需要：

```json
{
  "cluster_id": "cluster-1",
  "issuer": "https://issuer.example",
  "policy_version": "sa-policy-v1",
  "grant_format": "compact-jws",
  "signing_key_id": "eaa-2026-01",
  "signing_key_file": "secrets/eaa-private-key.pem",
  "proof_replay_state_file": "state/proof-replay.json",
  "grant_ledger_file": "state/grants.json",
  "max_token_lifetime_seconds": 3600,
  "registrations": []
}
```

Signer 至少需要：

```json
{
  "cluster_id": "cluster-1",
  "issuer": "https://issuer.example",
  "policy_version": "sa-policy-v1",
  "allow_legacy_token_grant": false,
  "eaa_keys": {"eaa-2026-01": "REPLACE_BASE64URL_ED25519_PUBLIC_KEY"},
  "kms_provider": "infisical",
  "kms_endpoint": "https://infisical.example",
  "kms_auth_token_file": "secrets/infisical-kms-token",
  "revocation_endpoint": "https://authority.example/v1/grants/status",
  "ledger_state_file": "state/signer-ledger.json",
  "key_generations": [{
    "generation": "generation-1",
    "key_id": "jwt-2026-01",
    "key_ref": "REPLACE_INFISICAL_KMS_KEY_UUID",
    "public_key": "REPLACE_BASE64_DER_PUBLIC_KEY",
    "algorithm": "RS256",
    "state": "Active"
  }],
  "max_token_lifetime_seconds": 3600
}
```

正常 signer 必须配置 `kms_endpoint`。将 `kms_provider` 设为 `infisical` 即可使用 Infisical 原生 KMS API；省略该字段或设为 `http` 时继续使用通用的受限 HTTP adapter。Infisical provider 还需要 signer 本地的 `kms_auth_token_file` bearer token 文件；该文件不能放进 Kubernetes 控制面对象，也不能提交到仓库。每个 `key_ref` 必须填写 Infisical KMS key UUID，`key_id` 仍然是 issuance/JWT 对外发布的逻辑标识。

Signer 使用的 Infisical key 必须处于 enabled 状态、用途为 `sign-verify` 且不可导出。Adapter 在本地组装 JWT header 和 payload，只把 JWS signing input 交给 Infisical，并使用 Infisical public key 本地验证返回的签名。CA 和 etcd X.509 signer 也使用同一边界：本地构造 leaf/intermediate chain，只把 intermediate certificate signature 交给 Infisical。

如果 signer token 只使用 `Cryptographic Operator` 权限，每个 generation 都必须在 `public_key` 中配置 Infisical `public-key` endpoint 返回的公钥材料（base64 DER 或 PEM）。这样运行时只调用签名 API，adapter 不会执行 key management read。Project Admin 只用于测试阶段的 key 生命周期和初始化配置。

`--allow-local-key-provider` 和 `local_key_files` 仅用于开发测试，会让 signer 进程接触可导出的私钥，不能用于生产。

Node-agent 至少需要 authority/signer endpoint、worker identity、identity key，以及按 `namespace/name` 配置的 binding。当前命令使用静态 `bindings` 只用于 bootstrap/test；生产 agent 必须替换为基于 attestation 的 resolver，并提供不可变的 ServiceAccount UID、Pod UID、audience、issuer 和 generation。

Authority 和 signer 默认监听 loopback，node-agent 默认监听 `unix:///var/run/sa-node-agent.sock`。非 loopback TCP listener 必须提供 `--tls-cert-file` 和 `--tls-key-file`；Unix socket 创建为 `0600`。这些参数只建立 server-side TLS；双向 TLS、服务身份、HA ledger、持久审计和 KMS 恢复仍是额外部署控制，本参考配置没有声称提供。

## 协议边界

现有 SA direct path 的 endpoint 和 JSON 字段形状仍然保留。默认使用 `issuance/v1` Compact JWS：authority 使用 `grant_format=compact-jws`（也可以省略），signer 保持 `allow_legacy_token_grant=false`。此模式下公共 core 只校验类型化 Compact JWS 契约。

仍使用旧 API-server carrier 的迁移部署，需要把 authority 的 `grant_format` 设为 `legacy-token-grant`，把 signer 的 `allow_legacy_token_grant` 设为 `true`。此时 authority 返回旧的 canonical JSON `TokenGrant` object，signer 接受没有新的 `X-Issuance-Identity` header 的请求。SA adapter 校验旧的 `ed25519-v1:<key-id>:<signature>` envelope，保留旧 binding digest 语义，然后在进入公共 core pipeline 前转换为类型化 Grant。node-agent `/v1/token` 兼容 envelope 返回 Kubernetes 风格的 `status.token` 和 `status.expirationTimestamp` 字段。

legacy 模式是显式开关，不能误开：它用于完成旧 carrier 迁移，新部署应使用 JWS。HA ledger、完整 mTLS identity provisioning、基于 attestation 的 workload resolver 以及生产 KMS/audit 部署仍是独立的生产门禁。

## 验证

```bash
GOCACHE=/tmp/k8s-credential-issuance-gocache go test ./...
GOCACHE=/tmp/k8s-credential-issuance-vetcache go vet -buildvcs=false ./...
GOCACHE=/tmp/k8s-credential-issuance-buildcache go build -buildvcs=false ./cmd/sa-authority ./cmd/sa-signer ./cmd/sa-node-agent
```

受限测试环境可能不允许监听 TCP，因此仓库内 HTTP E2E 使用 handler transport；它仍覆盖 authority、signer、两种 Grant response shape、legacy 转换、Grant 校验、KMS 边界、ledger 恢复、Kubernetes TokenRequest envelope 和 node-agent 请求链路。
