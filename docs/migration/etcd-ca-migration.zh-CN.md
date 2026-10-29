# etcd CA 迁移方案

**状态：** 方案归档，生产实施前仍需完成部署加固

**日期：** 2026-10-29

本文只覆盖一个 etcd 集群的 CA 私钥（通常为
`/etc/kubernetes/pki/etcd/ca.key`）从 master 节点迁移到离线 HSM/KMS，以及
peer/client 证书签发路径的分阶段切换。

本方案是 key custody 迁移，不更换现有 etcd CA 身份：保留原有 etcd CA
certificate、public key 和信任关系，不要求一次性重签所有 peer/client 证书。

## 1. 目标与边界

迁移完成后：

- master 节点不再持有可导出的 etcd CA private key；
- 原有 `etcd/ca.crt` 继续作为 etcd trust anchor；
- peer 和 client 日常证书分别由独立的 intermediate KMS key 签发；
- `etcd-signer` 不直接访问 etcd CA root private key；
- peer 证书按 quorum 安全约束逐个成员轮换；
- client 证书作为独立流程轮换，不改变 membership；
- old/new certificate path 可以审计、回滚和恢复。

本方案不包括更换 etcd CA certificate 本身。如果 etcd CA key 已疑似泄露，
需要另行设计 dual trust、全量证书重签和旧 CA 退役流程。

## 2. 目标拓扑

```text
原 etcd/ca.key
    -> 离线 HSM/KMS（保留相同 key material）
    -> 受控 ceremony 签发 peer/client intermediate

peer intermediate key -> KMS -> etcd-signer -> etcd peer certificates
client intermediate key -> KMS -> etcd-signer -> etcd client certificates

原 etcd/ca.crt
    -> etcd members 和 client verifiers 的 trust bundle
```

Peer 和 client 必须使用不同的 profile、purpose、key reference 和 policy。当前
仓库分别使用 `etcd-peer-certificate` 与 `etcd-client-certificate`，不能交叉
签发。

## 3. 迁移前盘点

以一个 etcd 集群为单位记录：

1. `etcd/ca.key`、`etcd/ca.crt` 的路径、权限、算法和 public key fingerprint；
2. CA key 与 CA certificate 是否匹配；
3. 集群 instance、member ID、peer URL、client URL 和 endpoint SAN；
4. 每个 member 的 peer cert/key、client cert/key、trusted CA file 和 reload
   方式；
5. etcd 启动参数、静态 Pod manifest、脚本和备份中的 CA private key 引用；
6. 当前 peer/client certificate issuer、有效期、role 和续期方式；
7. 当前 membership、healthy member 数量、quorum 和维护窗口；
8. 哪些 client identity 映射到 read/write/root role；
9. 证书安装、reload/restart、drain 和回滚路径。

盘点完成前，不应删除、覆盖或把 `etcd/ca.key` 复制到普通文件目录。

## 4. 验证并托管原 etcd CA key

在受控环境中：

1. 解析 CA private key 和 `etcd/ca.crt`；
2. 比较 private key public component 与 CA certificate public key；
3. 记录 CA certificate fingerprint、subject、issuer、有效期和 constraints；
4. 将同一份 key material 导入不可导出的 HSM/KMS，或移入离线 HSM；
5. 验证 HSM/KMS public key 与原 CA certificate 完全一致；
6. 禁止在线 `etcd-signer` 读取或导出 CA root private key。

当前仓库不提供通用 PEM-to-KMS import 命令。导入必须由目标 HSM/KMS 安全
流程完成，并保留双人复核、导入审计和受控恢复材料。

如果目标 KMS 无法保留原 CA public key，生成新 CA 就不再是 custody migration，
而是 etcd CA replacement。

## 5. 创建独立的 peer/client intermediate

在 external KMS/HSM 中分别生成不可导出的 peer 和 client intermediate key，
生成 CSR，并通过离线原 CA ceremony 签发对应 certificate：

```text
peer:
  purpose    = etcd-peer-certificate
  key_ref    = kms/etcd/peer-intermediate-2026-01
  key_id     = etcd-peer-2026-01
  generation = etcd-peer-generation-2026-01

client:
  purpose    = etcd-client-certificate
  key_ref    = kms/etcd/client-intermediate-2026-01
  key_id     = etcd-client-2026-01
  generation = etcd-client-generation-2026-01
```

两个 intermediate 必须分别满足：

- `CA=true`、适当的 path length 和有效期；
- peer 或 client 专属 profile、EKU、key usage 和 role policy；
- 到原 etcd CA certificate 的正确签名链；
- 独立的 KMS purpose、key reference、generation、operation-ID 和审计策略。

原 etcd CA certificate 可以作为 trust anchor 和 intermediate ancestor，但不能
作为在线 etcd signer 的通用 signing key reference。

## 6. 部署 etcd issuance 路径

配置 `etcd-authority`、`etcd-signer` 和 etcd certificate agent 使用独立的
服务身份、Grant key、KMS policy、ledger namespace 和 audit stream。

Authority 必须绑定并验证：

- cluster instance、member/client ID 和 identity；
- peer/client profile 和 endpoint SAN；
- CSR public key digest；
- generation、key ID、TTL 和 etcd role；
- member replacement、snapshot restore 等独立 workflow 的授权边界。

证书签发本身不能执行 membership mutation。Agent 应在 member 本地生成 key 和
CSR，签发结果只返回 leaf 加 intermediate chain；CA root certificate 继续由
member/client 的 trust bundle 提供。

当前仓库已经有 etcd authority、peer/client profile、signer、direct Agent、
文件安装器和 quorum-aware rotation controller，但还没有 `cmd/etcd-*` 的
生产进程入口和完整 etcd 集成适配器。

## 7. 先建立 trust，再轮换 peer

同一个 etcd 集群内必须先完成 trust 和 signer 验证，再逐个 member 轮换。

### 阶段 A：验证 intermediate certificate

- 在目标 member 本地生成新的 peer key/CSR；
- authority 根据 member identity、endpoint SAN 和 public key 签发 Grant；
- `etcd-signer` 使用 peer intermediate KMS key 签发；
- 验证 leaf -> peer intermediate -> 原 etcd CA chain；
- 确认 member 的 trusted CA 仍包含原 `etcd/ca.crt`；
- 在不影响现有 member 的条件下验证新证书安装、reload 和 TLS handshake。

### 阶段 B：逐个轮换 peer member

每次只处理一个 member，顺序必须是：

1. 确认当前 healthy member 数量满足 quorum；
2. 确认新旧 trust overlap 已就绪；
3. 通过 `CanRotatePeer` 检查轮换该 member 后仍满足 quorum；
4. 获取该 member 的新 peer certificate；
5. 原子安装证书，保留 private key 在 member 本地；
6. reload/restart，并等待该 member 恢复 healthy；
7. 执行 peer TLS、cluster health 和 endpoint 检查；
8. 记录结果后再处理下一个 member。

不得并行停止两个可能影响 quorum 的 member。证书签发不能替代 membership
change、member replacement 或 snapshot restore 的单独授权流程。

## 8. 独立轮换 client certificate

Peer rotation 完成并稳定后，单独迁移 client certificates：

- 使用 `etcd-client` profile 和 `etcd-client-certificate` purpose；
- authority 重新验证 client identity 和 read/write/root role；
- client CSR 的 public key、role、SAN 和 TTL 必须绑定到 Grant；
- 逐个 client 或 client pool 安装并验证；
- client certificate 不得使用 peer key 或 peer Grant；
- 不因 client certificate rotation 修改 etcd membership。

## 9. 从 master 移除 `etcd/ca.key`

完成以下检查后，才从 master 节点移除 etcd CA private key：

- 原 CA key 已在 HSM/KMS 中通过 fingerprint 校验；
- peer/client intermediate 已由原 CA 正确签发；
- peer 和 client signer 都能稳定签发并恢复相同请求的结果；
- 所有新的 peer/client issuance path 不再读取 master 上的 CA key；
- etcd 启动参数、manifest、脚本和备份流程没有残留在线引用；
- 所有 member 和 client verifier 仍可获得原 `etcd/ca.crt`；
- 至少完成一次 signer 重启、KMS timeout、member reload failure 和网络恢复测试；
- 已保存 quorum、迁移、回滚和恢复审计记录。

移除的是 master 上的 CA private key 副本。`etcd/ca.crt` 是 public trust
material，必须继续保留和分发。

## 10. 回滚与后续状态

在 CA key 从 master 移除前，可以暂停新 issuance 并恢复旧证书路径。移除后不
应把 CA private key 复制回 master；恢复必须使用 HSM/KMS ceremony。

迁移完成后：

1. 原 etcd CA certificate 继续作为 trust anchor；
2. peer 和 client intermediate generation 分别负责在线签发；
3. peer rotation 始终一次只处理一个 member，并保持 quorum；
4. client rotation 与 membership workflow 分离；
5. CA key 疑似泄露时立即停止使用并启动独立的 emergency replacement 流程。

## 11. 当前仓库支持和剩余工作

仓库已经提供：

- etcd peer/client typed Grant payload 和 profile 隔离；
- cluster/member/client identity、endpoint SAN、role、TTL 和 public key binding；
- peer/client purpose 分离的 KMS policy shape；
- etcd authority、signer、direct Agent 和 atomic file installer；
- `ValidateQuorum`、`CanRotatePeer` 和 peer/client rotation controller 接口；
- member replacement 和 snapshot restore 的 authority workflow reference。

迁移前仍需要完成或由部署系统提供：

- exact etcd CA key import/offline HSM ceremony；
- peer/client intermediate CSR 签发和 KMS metadata provisioning；
- `etcd-authority`、`etcd-signer`、certificate agent 的生产命令入口；
- 真实 etcd 集成、member health probe、reload/restart、drain 和 rollback adapter；
- HA registry/ledger、mTLS identity、持久 audit 和 failure injection；
- member/client private-key 引用扫描和 CA key 删除审计。

因此，本仓库当前是可测试的 etcd issuance/rotation 参考路径，不是完成的生产
迁移工具。

## 12. 验收标准

一个 etcd 集群的 CA 迁移满足以下条件才算完成：

1. etcd CA certificate fingerprint 和 public key 与迁移前一致；
2. `etcd/ca.key` 不再存在于 master 节点或普通 signer 文件系统；
3. peer 和 client 使用独立的 intermediate key、purpose、profile 和 Grant；
4. 新 peer/client chain 可由原 `etcd/ca.crt` 验证；
5. peer rotation 每次只影响一个 member，并始终保持 quorum；
6. client rotation 不修改 membership，role binding 可审计；
7. 旧证书在有效期内继续工作，新证书 reload/restart 和 TLS 检查通过；
8. KMS、authority、ledger 或 etcd health 不确定时不会触发本地 signing fallback；
9. rollback、恢复、quorum 和 CA ceremony 均有审计记录。

## 相关文档

- [Credential Issuance Contract v1](../contracts/issuance-v1.zh-CN.md)
- [外部组件实现方案](../architecture/k8s-credential-issuance-platform-implementation.zh-CN.md)
