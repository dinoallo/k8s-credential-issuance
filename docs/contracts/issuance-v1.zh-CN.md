# Credential Issuance Contract v1

**状态：** 已冻结契约
**日期：** 2026-10-28
**仓库：** k8s-credential-issuance
**领域：** ca、sa、etcd

本文冻结 Kubernetes CA Issuance V2、ServiceAccount JWT Issuance V2 和 etcd CA Issuance V2 共同使用的协议与安全边界，定义 external authority、signer、Agent、ledger 和 KMS 的契约。不限定具体编程语言、数据库或部署平台。

## 1. 规范用语与安全边界

MUST、MUST NOT、SHOULD 和 MAY 表示规范要求。

Kubernetes 控制面是不可信的传输和存储平面，不能持有 CA 私钥、ServiceAccount JWT signing key、EAA Grant signing key、signer credential、KMS management credential 或 HSM/KMS 私钥材料。

平台使用一个公共 core、三个领域插件和多个隔离运行实例。共享代码不能意味着共享凭据、签名 key、无限制策略或跨领域授权。

## 2. Domain 与版本

每个请求和 Grant 必须且只能包含一个 domain：

~~~text
ca       Kubernetes X.509 certificate issuance
sa       ServiceAccount JWT issuance
etcd     etcd peer/client certificate issuance
~~~

契约版本为 issuance/v1。每个运行实例必须固定配置为一个 domain，并拒绝其他 domain。未知版本、domain、算法或必填字段必须拒绝。

## 3. Grant 契约

Grant 使用 Compact JWS：

~~~text
alg = EdDSA
key type = Ed25519
payload canonicalization = RFC 8785 JCS
~~~

Protected header 必须包含 alg、kid、typ 和 ver。推荐类型为 issuance-grant+jws。禁止 alg=none、算法替换、压缩、external Grant lookup 和由请求方选择验证 key。Signer 只能从本领域配置的 kid allowlist 选择 EAA 公钥。

Canonical payload 必须包含：

~~~text
version
domain
grant_id
request_id
identity_ref
binding_digest
generation
key_id
policy_version
not_before
expires_at
nonce
typed_payload
~~~

请求 lifetime 必须与 Grant lifetime 完全相等，且不能超过 profile 最大 TTL。binding_digest 是领域 canonical binding 的 SHA-256 digest。grant_id、request_id 和 nonce 必须具有足够熵。时间使用 UTC。

CA carrier 限制为：

~~~text
decoded DER CSR <= 64 KiB
Grant JWS <= 16 KiB
total V2 annotations <= 32 KiB
compression = forbidden
~~~

其他领域在生产部署前必须定义等价的请求和响应大小上限。

## 4. 领域 binding

### 4.1 CA

CA binding 必须包含：

~~~text
csr_request_digest
public_key_sha256
signer_name
profile
subject
dns_names
ip_addresses
uris
key_usages
extended_key_usages
requested_lifetime
generation
key_id
~~~

Signer 必须从 allowlist profile 构造最终 X.509 template。每个 profile 必须定义身份策略、最大 TTL、允许的 SAN/EKU、generation 策略和 KMS key allowlist。禁止调用方提供无限制证书 template。

### 4.2 ServiceAccount JWT

SA binding 必须包含：

~~~text
claims_digest
serviceaccount_uid
pod_uid              # Pod-bound workload 必填
audience
issuer
cluster_id
requested_lifetime
generation
key_id
~~~

Signer 必须根据验证过的 binding 和策略生成 JWT claims。禁止任意 claims 和通用 JWT/字节签名 endpoint。

完整 V2 worker authorization 使用可信 direct worker provider 或 node-agent。只通过不可信 API Server annotation relay 传递 Grant 属于兼容传输，不构成完整 worker authorization path。

### 4.3 etcd

etcd binding 必须包含：

~~~text
cluster_instance
member_id_or_client_id
member_or_client_identity
endpoint_sans
profile             # etcd-peer 或 etcd-client
etcd_roles
public_key_sha256
requested_lifetime
generation
key_id
~~~

Peer 和 client profile 必须使用独立策略和 CA key reference。Client Grant 不能授权 peer certificate，peer Grant 也不能授权 client certificate。Membership change、snapshot restore 和 member replacement 属于独立授权 workflow，证书签发本身不能修改 membership。

## 5. 请求与响应 carrier

公共 core 支持 direct request 和受限 relay request。Carrier 不能改变已签名 binding。

CA 兼容 carrier 使用：

~~~text
spec.request                         DER PKCS#10 CSR
metadata.annotations[ca-grant]       完整 Compact JWS Grant
metadata.annotations[request-id]     Grant request_id
spec.expirationSeconds               与 Grant lifetime 完全相等
~~~

生产 annotation prefix 必须使用实际拥有的 DNS prefix。CSR watch event 只能作为队列触发；signer 必须重新读取最新 CSR，只更新 certificatesigningrequests/status，不能把 Approved 当作外部授权。

CA 成功时，status.certificate 按 leaf-first 写入 PEM leaf 和 intermediate chain，不写 Root。status.ca 保持为空，不作为 trust-bundle 通道。

完整 SA 路径使用经过认证的 worker/provider direct request，把绑定后的 JWT 返回给 node-agent 或 kubelet provider。JWKS 和 key metadata 通过单独受保护的 verifier discovery channel 发布。

etcd 应优先使用 Agent 到 signer 的 direct request。受约束 CSR relay 只有在 signer 重新读取请求、校验完整 binding 并只写 CSR status 时才允许使用。Direct 和 relay 必须具有相同的 Grant、digest、幂等和结果语义。

## 6. Authority 契约

External authority 必须提供：

- 领域身份和 profile 注册；
- 独立身份或 attestation 校验；
- 带签名的单次 Grant 签发；
- identity、request、公钥、profile、lifetime、generation 和 key 的精确绑定；
- 未消费 Grant 撤销；
- generation blocking 和 emergency disable；
- 独立授权审计流。

Authority 不能只使用 master-held kubeconfig、ServiceAccount token、CSR approval、Kubernetes Node object 或 initial-cluster value 作为授权来源。

Authority signing key 必须按安全领域分离，或由等价的领域级边界保护。Signer 只能信任本领域配置的 authority key set。

## 7. Signer 契约

Signer 必须：

1. 使用领域身份认证请求；
2. 通过领域插件解析并 canonicalize 请求；
3. 校验 JWS、kid、有效期、generation 和 policy version；
4. 重新计算并比较 binding_digest；
5. 校验公钥、profile、身份、lifetime 和领域字段；
6. 原子 reserve Grant；
7. 生成受限 SigningIntent；
8. 授权成功后才能调用 KMS；
9. 在交付前持久化完整结果；
10. 通过领域 carrier 交付结果；
11. 审计成功、拒绝、重试和恢复。

Signer 不能 approve CSR、读取 Secret、创建 Pod、修改 Node/RBAC、使用 admin.conf、签任意字节或无限制 template、复制私钥到本地/Kubernetes 存储，或回退到本地签名、auto-TLS、明文和不可信 local key。

## 8. Ledger 与幂等契约

Ledger 位于控制面信任边界之外，并支持多个 signer 实例之间的原子操作。

最小状态模型：

~~~text
issued
reserved
signing
completed
retryable_failure
permanent_failure
revoked
~~~

reserve 必须原子地把第一个请求绑定到 Grant。之后如果 digest、公钥、身份、profile 或 target UID 变化，必须拒绝。

Reservation 必须包含稳定的 operation_id，相同请求重试时复用。KMS 成功后，完整证书或 JWT result 必须在交付前持久化。交付失败后的重试必须返回完全相同的结果。Grant 在并发、重连和重试之间只能消费一次。

临时 ledger、KMS、audit 或 API conflict 保持可重试；授权和 binding 违规属于永久失败。不确定状态必须 fail-closed。

## 9. KMS 契约

KMS adapter 必须使用不可导出私钥、受限领域签名、key/generation/algorithm/purpose allowlist、key version、disable/retirement、审计、短期 machine identity 或 mTLS，以及 operation-ID 幂等或结果恢复。

CA 和 etcd key 必须支持批准的 X.509 兼容签名；SA key 必须支持批准的 JWT 算法。KMS management credential 必须位于控制面之外。

内部接口是受限 intent，而不是 Sign(arbitraryBytes)：

~~~text
SigningIntent {
  domain
  purpose
  key_id
  generation
  algorithm
  operation_id
  payload_digest
}
~~~

如果 KMS 不具备非对称签名、不可导出、审计和结果恢复能力，则不能作为本契约的生产签名 backend。

## 10. 错误、重试与 fail-closed

永久失败包括签名无效、未知 key、Grant 过期、binding 不匹配、replay、profile 违规、身份不匹配和跨领域使用，必须产生终态失败和审计事件。

临时失败包括 API conflict、ledger 不可用、KMS timeout 且结果未知、audit store 不可用和 authority 临时失败。必须保持可重试，不能生成新 Grant 或修改原请求。

当授权、ledger、audit 或 KMS 结果不确定时，不能签发不同 artifact 或使用本地 fallback。恢复必须使用已记录的 operation_id 和 ledger result。

## 11. Generation、trust 与轮换

每个领域和 profile/generation 都有独立 key reference、policy、audit stream 和 disable action。

轮换必须支持 active/previous overlap、新公钥或 trust bundle 发布、Grant 切换到新 generation、leaf/token renewal、connection/cache drain、紧急撤销和 disable、reload/restart 与 drain 后移除旧 trust，以及不复制私钥到控制面的恢复。

禁用 key 会停止新签名，但不会立即撤销已签发 artifact。Consumer 和 trust-bundle controller 必须执行文档化的接受窗口。

## 12. 运行时隔离

生产实例必须拥有固定 domain、独立服务和 mTLS identity、领域专用 authority public key、KMS key/purpose allowlist、ledger namespace、按服务授权、网络出口策略、审计权限和告警。

推荐实例：

~~~text
ca-authority    -> ca-signer    -> CA KMS keys
sa-authority    -> sa-signer    -> SA JWT KMS keys
etcd-authority  -> etcd-signer  -> etcd peer/client KMS keys
~~~

只有在这些隔离控制可执行且已测试时，才允许共享数据库、KMS endpoint 或 binary。

## 13. 契约测试

实现必须证明：

1. 一个领域的 Grant 会被其他所有领域 signer 拒绝；
2. 修改 identity、公钥、profile、SAN、role、endpoint、generation 或 lifetime 会被拒绝；
3. 并发 signer 只能消费一次 Grant；
4. KMS 成功但交付失败时重试返回原始结果；
5. 没有公开 API 可以签任意字节或无限制 template；
6. authority、ledger、KMS、audit 和控制面故障会对新签发 fail-closed；
7. etcd peer 和 client key 不能交叉签发；
8. CA status、SA JWT/JWKS 和 etcd certificate delivery 保持各自领域契约。

## 14. 兼容性与变更策略

本文是 v1 契约。对 Grant 编码、签名字段、binding 语义、KMS intent、ledger 状态或结果语义的变更，必须创建新契约版本，或明确声明为兼容的版本化扩展。

编程语言、数据库产品、部署编排器和内部 package 名称可以变化，只要不改变本文契约。

## 相关文档

- [外部组件实现方案](../architecture/k8s-credential-issuance-platform-implementation.zh-CN.md)
