# Helm 部署

仓库在 [`charts/k8s-credential-issuance`](../../charts/k8s-credential-issuance/) 提供了参考 Helm Chart，用于把当前的 `sa-authority`、`sa-signer` 和 `sa-node-agent` 命令二进制部署为 Kubernetes 工作负载。

Chart README 包含安装示例、values 结构、Secret 处理、TLS 设置、node-agent socket 接入方式，以及文件型参考存储的限制：

- [Chart README](../../charts/k8s-credential-issuance/README.zh-CN.md)
- [ServiceAccount 部署参考](./sa-issuance.zh-CN.md)

这个 Chart 有意不宣称提供 HA 或生产就绪能力。在隔离的参考环境之外使用前，请配置外部 KMS、attestation 服务、mTLS 身份、持久审计链路和支持事务的 ledger。

## 生产集群与外部 issuance 集群分离部署

生产环境请将 issuance 服务和 node-agent 拆成两个 Helm release：

1. 在 issuance 集群中安装 authority 和 signer，并关闭 node-agent：

   ```yaml
   authority:
     enabled: true
   signer:
     enabled: true
   ingress:
     enabled: true
     className: nginx
     annotations:
       nginx.ingress.kubernetes.io/backend-protocol: HTTPS
   nodeAgent:
     enabled: false
   ```

   ```bash
   helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
     --namespace issuance --create-namespace \
     --values ./values-issuance.yaml
   ```

2. 在每个业务集群中只安装 node-agent，并为外部服务设置明确的 HTTPS endpoint：

   ```yaml
   authority:
     enabled: false
   signer:
     enabled: false
   nodeAgent:
     enabled: true
     config:
       authority_endpoint: https://sa-authority.issuance.example/v1/grants
       signer_endpoint: https://sa-signer.issuance.example/v1/sign
   ```

   ```bash
   helm upgrade --install kci-node-agent ./charts/k8s-credential-issuance \
     --namespace kube-system \
     --values ./values-node-agent.yaml
   ```

默认 endpoint helper 假设所有组件共享同一个 release 和 Namespace，拆分 release 后必须覆盖 endpoint。如果是不同集群，请通过内部 LoadBalancer、Gateway 或等价私有网络路径暴露 issuance 服务；ClusterIP 和 `*.svc.cluster.local` 地址不能作为跨集群 endpoint。Authority/signer Secret 应创建在 issuance 集群，每个业务集群创建自己的 node identity Secret。当前 Chart 的一个 node-agent DaemonSet 使用同一份配置的 identity 和 key；如果需要每节点独立身份，还需要额外的身份注入机制或拆分 release。

当 `ingress.enabled: true` 时，Chart 会为 authority 和 signer host 创建标准的 `networking.k8s.io/v1` Ingress。Ingress controller 和 TLS Secret 必须由集群平台提供；Chart 不会安装这两者。如果 authority 和 signer Service 使用 HTTPS，还需要设置对应 Ingress controller 的 backend protocol annotation。
