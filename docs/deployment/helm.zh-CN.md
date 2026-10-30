# Helm 部署

仓库在 [`charts/k8s-credential-issuance`](../../charts/k8s-credential-issuance/) 提供了参考 Helm Chart，用于把当前的 `sa-authority`、`sa-signer` 和 `sa-node-agent` 命令二进制部署为 Kubernetes 工作负载。

Chart README 包含安装示例、values 结构、Secret 处理、TLS 设置、node-agent socket 接入方式，以及文件型参考存储的限制：

- [Chart README](../../charts/k8s-credential-issuance/README.zh-CN.md)
- [ServiceAccount 部署参考](./sa-issuance.zh-CN.md)

这个 Chart 有意不宣称提供 HA 或生产就绪能力。在隔离的参考环境之外使用前，请配置外部 KMS、attestation 服务、mTLS 身份、持久审计链路和支持事务的 ledger。
