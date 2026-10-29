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
  "kms_endpoint": "https://kms.example",
  "revocation_endpoint": "https://authority.example/v1/grants/status",
  "ledger_state_file": "state/signer-ledger.json",
  "key_generations": [{
    "generation": "generation-1",
    "key_id": "jwt-2026-01",
    "key_ref": "kms/sa/jwt-2026-01",
    "algorithm": "RS256",
    "state": "Active"
  }],
  "max_token_lifetime_seconds": 3600
}
```

正常 signer 必须配置 `kms_endpoint`。`--allow-local-key-provider` 和 `local_key_files` 仅用于开发测试，会让 signer 进程接触可导出的私钥，不能用于生产。

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
