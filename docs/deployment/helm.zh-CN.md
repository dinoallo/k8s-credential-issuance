# Helm 部署

仓库在 [`charts/k8s-credential-issuance`](../../charts/k8s-credential-issuance/) 提供了参考 Helm Chart，用于把当前的 `sa-authority`、`sa-signer`、`sa-attestor` 和 `sa-node-agent` 命令二进制部署为 Kubernetes 工作负载。

Chart README 包含安装示例、values 结构、Secret 处理、TLS 设置、node-agent socket 接入方式，以及文件型参考存储的限制：

- [Chart README](../../charts/k8s-credential-issuance/README.zh-CN.md)
- [ServiceAccount 部署参考](./sa-issuance.zh-CN.md)

这个 Chart 有意不宣称提供 HA 或生产就绪能力。在隔离的参考环境之外使用前，请配置外部 KMS、mTLS 身份、持久审计链路和支持事务的 ledger。启用 attestor 后，Chart 会创建独立 ServiceAccount，并只授予 Pods 和 ServiceAccounts 的 `get` 权限；proof key 和 mTLS 材料仍需由部署平台 provisioning。

## Authority 签名私钥 Secret

在安装 issuance 集群 release 前，只生成或初始化一次 Authority 的 EAA Ed25519 私钥。二进制要求 Secret 中存在名为 `eaa-private-key.pem` 的 PKCS#8 PEM 文件：

```bash
kubectl create namespace issuance
openssl genpkey -algorithm Ed25519 -out eaa-private-key.pem
chmod 600 eaa-private-key.pem
kubectl -n issuance create secret generic sa-authority-signing-key \
  --from-file=eaa-private-key.pem=./eaa-private-key.pem
```

在 values 中显式引用：

```yaml
authority:
  signingKey:
    secretName: sa-authority-signing-key
    key: eaa-private-key.pem
```

把匹配的公钥使用相同的 `signing_key_id` 配置到
`signer.config.eaa_keys`，并在 Helm 升级过程中保持私钥不变。如果不设置
`authority.signingKey.secretName`，Chart 会根据 release 名称生成 Secret 名称，例如
`kci-issuance-k8s-credential-issuance-authority-signing-key`，但不会创建该 Secret。生产环境请在 Helm 外部创建私钥 Secret；Chart 的 `--set-file` 方式只适用于受控测试环境。

## Signer KMS token Secret

正常 signer 配置使用 Infisical provider。请单独准备 Infisical bearer token，并创建一个数据 key 为 `token` 的 Secret：

```bash
kubectl -n issuance create secret generic sa-signer-kms \
  --from-file=token=./infisical-kms-token
```

在 values 文件中引用：

```yaml
signer:
  kms:
    provider: infisical
    authToken:
      secretName: sa-signer-kms
      key: token
```

如果不设置 `signer.kms.authToken.secretName`，名为 `kci-issuance` 的 release 会引用但不会创建
`kci-issuance-k8s-credential-issuance-signer-kms`。如果使用这个默认名称，请按下面的方式创建 Secret，并从 values 中省略 `secretName`：

```bash
kubectl -n issuance create secret generic \
  kci-issuance-k8s-credential-issuance-signer-kms \
  --from-file=token=./infisical-kms-token
```

生产环境请在 Helm 外部创建这个 Secret；Chart 的 `--set-file` token 方式只适用于受控测试。使用通用 `http` KMS provider 不需要 Infisical token Secret。

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
   attestor:
     enabled: false
   ```

   ```bash
   helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
     --namespace issuance --create-namespace \
     --values ./values-issuance.yaml
   ```

2. 在每个业务集群中安装 node-agent；如果 attestor 也运行在业务集群，则同时启用它并配置 Kubernetes API RBAC 和 mTLS Secret：

   ```yaml
   authority:
     enabled: false
   signer:
     enabled: false
   attestor:
     enabled: true
     tls:
       enabled: true
       secretName: sa-attestor-tls
     attestorKey:
       secretName: sa-attestor-key
   nodeAgent:
     enabled: true
     attestationTLS:
       enabled: true
       secretName: sa-node-attestor-tls
     config:
       authority_endpoint: https://sa-authority.issuance.example/v1/grants
       signer_endpoint: https://sa-signer.issuance.example/v1/sign
       attestation_endpoint: https://kci-node-agent-k8s-credential-issuance-attestor:9445/v1/attest
   ```

   ```bash
   helm upgrade --install kci-node-agent ./charts/k8s-credential-issuance \
     --namespace kube-system \
     --values ./values-node-agent.yaml
   ```

默认 endpoint helper 假设所有组件共享同一个 release 和 Namespace，拆分 release 后必须覆盖 endpoint。如果是不同集群，请通过内部 LoadBalancer、Gateway 或等价私有网络路径暴露 issuance 服务；ClusterIP 和 `*.svc.cluster.local` 地址不能作为跨集群 endpoint。Authority/signer Secret 应创建在 issuance 集群，业务集群创建 attestor、node-agent attestation 和 node identity Secret。当前 Chart 的一个 node-agent DaemonSet 使用同一份配置的 identity 和 key；如果需要每节点独立身份，还需要额外的身份注入机制或拆分 release。

当 `ingress.enabled: true` 时，Chart 会为 authority 和 signer host 创建标准的 `networking.k8s.io/v1` Ingress。Ingress controller 和 TLS Secret 必须由集群平台提供；Chart 不会安装这两者。如果 authority 和 signer Service 使用 HTTPS，还需要设置对应 Ingress controller 的 backend protocol annotation。
