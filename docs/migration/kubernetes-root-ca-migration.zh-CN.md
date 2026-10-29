# Kubernetes Root CA 迁移方案

**状态：** 方案归档，生产实施前仍需完成部署加固

**日期：** 2026-10-29

本文只覆盖一个 Kubernetes 集群中 root CA 私钥（通常为
`/etc/kubernetes/pki/ca.key`）从 master 节点迁移到离线 HSM/KMS 的方案。

本方案是 key custody 迁移，不更换现有 root CA 身份：保留原有 root 证书、
public key、subject 和信任关系，不要求一次性重签所有已经存在的叶子证书。

## 1. 目标与边界

迁移完成后：

- master 节点不再持有可导出的 `ca.key`；
- 原有 `ca.crt` 继续作为 trust anchor 分发和使用；
- 日常叶子证书签发使用由 root CA 签发的 intermediate key；
- `ca-signer` 不直接访问 root private key，也不使用 root key 做在线通用签名；
- 现有 root 签发的叶子证书在有效期内继续有效；
- 新签发路径、trust bundle 和证书轮换可以独立审计。

本方案不包括更换 root CA 证书本身。如果 root key 已疑似泄露，需要另行设计
双 root trust overlap、全量叶子重签和旧 root 退役流程。

## 2. 目标拓扑

```text
原 ca.key
    -> 离线 HSM/KMS（保留相同 key material）
    -> 受控 ceremony 签发 CA intermediate

CA intermediate private key
    -> external KMS
    -> ca-signer
    -> ca-authority / CA agent
    -> Kubernetes 叶子证书

原 ca.crt
    -> master、node 和其他 verifier 的 trust bundle
```

`ca-signer` 只使用 intermediate 的 `key_ref`。当前仓库的 X.509 参考 backend
明确要求 issuer 是 intermediate，拒绝 self-signed root；证书响应只返回
leaf 加 intermediate，不返回 root。

## 3. 迁移前盘点

以一个集群为单位记录：

1. `ca.key`、`ca.crt` 的路径、权限、算法和 public key fingerprint；
2. `ca.key` 与 `ca.crt` 是否匹配；
3. kube-apiserver、controller-manager、CSR controller、脚本和备份中所有
   root private key 引用；
4. 当前哪些组件直接使用 root key 签发证书，哪些只验证 `ca.crt`；
5. 所有 leaf certificate 的 issuer、有效期、用途和续期方式；
6. 节点和组件的 trust bundle 分发路径；
7. 当前 CSR carrier、签发服务和证书安装/reload 路径；
8. 可以接受的证书轮换窗口和回滚窗口。

在盘点完成前，不应从 master 删除、覆盖或复制 `ca.key` 到新的普通文件目录。

## 4. 验证并托管原 root key

先在受控环境中：

1. 解析 `ca.key` 和 `ca.crt`；
2. 比较 private key public component 与 `ca.crt` public key；
3. 记录 root certificate fingerprint、subject、issuer、有效期和 constraints；
4. 将同一份 root key material 导入不可导出的 HSM/KMS，或移入离线 HSM；
5. 验证 HSM/KMS 返回的 public key 与原证书完全一致；
6. 禁止任何在线 signer 读取或导出该 root private key。

当前仓库不提供通用 PEM-to-KMS import 命令。导入必须由目标 HSM/KMS 的
安全运维流程完成，并保留双人复核、导入审计和受控恢复材料。

如果目标 KMS 无法保留原 root public key，不能把生成的新 root 当作等价迁移；
那会变成 root CA replacement，需要另一套方案。

## 5. 创建并发布 CA intermediate

使用 external KMS/HSM 生成不可导出的 intermediate private key，得到 CSR，
再通过离线 root ceremony 签发 intermediate certificate。记录：

```text
purpose    = ca-certificate
key_ref    = kms/ca/intermediate-2026-01
key_id     = ca-intermediate-2026-01
generation = ca-generation-2026-01
profile    = 按批准的 CA profile
```

Intermediate 必须明确：

- `CA=true` 和适当的 path length；
- 允许的签发用途、profile 和 signer；
- 有界的有效期和 generation；
- 与 root certificate 的正确签名链；
- KMS 中的不可导出、purpose、algorithm、operation-ID 和审计策略。

Root certificate 可以作为 intermediate 的上级链材料保存，但不应作为在线
`ca-signer` 的 signing key reference。

## 6. 部署 CA issuance 路径

配置 `ca-authority`、`ca-signer` 和 CA agent 使用独立的服务身份、Grant key、
KMS key reference、ledger namespace 和 audit stream。

CA Grant 必须继续绑定：

- identity、CSR digest 和 public key digest；
- signer name、profile、Subject、SAN、EKU 和 key usage；
- generation、key ID、TTL 和 policy version。

新的签发路径可以使用 direct request 或受限 CSR carrier。CSR event 只能作为
队列触发，signer 必须重新读取最新 CSR，只更新 status，不能把 Approved 当作
外部授权。

证书交付遵循 leaf-first 规则：

```text
status.certificate = leaf PEM + intermediate PEM
status.ca          = empty
```

Root `ca.crt` 继续通过独立 trust-bundle channel 分发，不能把 `status.ca` 当作
root trust channel。

当前仓库已经有 CA plugin、authority、signer、Agent、CSR status controller 和
rotation controller 的参考实现，但还没有 `cmd/ca-*` 的生产进程入口。

## 7. 分阶段切换叶子证书

同一个集群内逐类、逐组件迁移，不要求同时重签所有证书：

### 阶段 A：验证 intermediate 签发

- 用新 CA profile 生成本地 key 和 CSR；
- 通过 authority 获取 Grant；
- 由 `ca-signer` 使用 intermediate KMS key 签发；
- 验证 leaf -> intermediate -> 原 root 的链；
- 验证返回内容不包含 root；
- 安装证书并执行组件 reload/restart；
- 验证旧 root-signed leaf 和新 intermediate-signed leaf 都能被现有
  `ca.crt` 验证。

### 阶段 B：逐类轮换

按低风险到高风险的顺序迁移各类 leaf certificate。每次只处理一个明确的
profile 或组件集合，并在下一批之前确认：

- 新证书已经安装并生效；
- 对端仍能完成 TLS 验证；
- reload/restart 后没有重新读取 `ca.key`；
- 旧证书仍保留为可控回滚材料；
- authority、signer、KMS、ledger 和 audit 状态正常。

旧 leaf certificate 不需要因为 root key 离开 master 而立即失效；只有签发新
证书的路径需要切换到 intermediate。

## 8. 从 master 移除 `ca.key`

完成以下检查后，才从 master 节点移除 root private key：

- root key 已在 HSM/KMS 中通过 fingerprint 校验；
- intermediate certificate 已由原 root 正确签发；
- CA signer 已能稳定签发和恢复相同请求的结果；
- 所有新证书签发路径不再读取 master 上的 `ca.key`；
- kube-apiserver、controller-manager、脚本和 manifest 没有残留引用；
- `ca.crt` 已在所有需要验证的组件上保持可用；
- 至少完成一次 signer 重启、KMS timeout、CSR conflict 和 reload 失败测试；
- 已保存迁移审计、备份和回滚材料。

移除的是 master 上的 private key 副本。`ca.crt` 是 public trust material，
必须继续保留和分发。

## 9. 回滚与后续状态

在 master 私钥移除前，回滚可以暂停新路径并恢复旧签发流程；移除后不应把
root private key 复制回 master。后续恢复应使用 HSM/KMS ceremony 和相同的
operation/审计流程。

迁移完成后：

1. 原 root certificate 继续作为 trust anchor；
2. CA intermediate generation 负责日常在线签发；
3. root key 仅用于受控的 intermediate、灾备或明确授权操作；
4. leaf rotation、trust bundle 发布和 root ceremony 分别审计；
5. 如果 root key 疑似泄露，立即停止使用并启动独立的应急替换流程。

## 10. 当前仓库支持和剩余工作

仓库已经提供：

- 有界 CSR 解析和 public key digest binding；
- CA profile、SAN、EKU、key usage、TTL 和 generation 校验；
- CA authority、Grant、signer、Agent 和 CSR status controller；
- intermediate-only 的 X.509 chain 输出和 root rejection；
- CA rotation controller 的安装、reload 和结果校验接口。

迁移前仍需要完成或由部署系统提供：

- exact root-key import/offline HSM ceremony；
- intermediate CSR 签发、KMS policy 和 public metadata provisioning；
- `ca-authority`、`ca-signer`、CA agent 的生产命令入口；
- HA ledger、mTLS identity、持久 audit 和 trust-bundle controller；
- 各 Kubernetes 组件的证书安装、reload/restart 和回滚适配器；
- master private-key 引用扫描与删除审计。

因此，本仓库当前是可测试的 CA issuance 参考路径，不是完成的生产迁移工具。

## 11. 验收标准

一个集群的 root CA 迁移满足以下条件才算完成：

1. root certificate fingerprint 和 public key 与迁移前一致；
2. `ca.key` 不再存在于 master 节点或普通 signer 文件系统；
3. `ca-signer` 只能访问 intermediate KMS key；
4. 新 leaf chain 为 leaf + intermediate，并可由原 `ca.crt` 验证；
5. 现有 root-signed leaf 在有效期内不受影响；
6. 新旧证书路径均完成 reload/restart 和 TLS 验证；
7. KMS、authority、ledger、audit 或控制面故障不会触发本地 signing fallback；
8. 回滚、恢复和 root ceremony 都有审计记录。

## 相关文档

- [Credential Issuance Contract v1](../contracts/issuance-v1.zh-CN.md)
- [外部组件实现方案](../architecture/k8s-credential-issuance-platform-implementation.zh-CN.md)
