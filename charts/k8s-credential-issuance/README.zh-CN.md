# k8s-credential-issuance Helm Chart

这个 Chart 部署仓库当前实际包含的三个可运行组件：

| 组件 | Kubernetes 工作负载 | 默认端点 |
| --- | --- | --- |
| `sa-authority` | 单副本 Deployment 和 ClusterIP Service | `http://<release>-k8s-credential-issuance-authority:9441` |
| `sa-signer` | 单副本 Deployment 和 ClusterIP Service | `http://<release>-k8s-credential-issuance-signer:9444` |
| `sa-node-agent` | 带节点本地 Unix socket 的 DaemonSet | `/var/run/k8s-credential-issuance/sa-node-agent.sock` |

这个 Chart 是参考实现的部署封装，不会把文件型 ledger 自动变成 HA 存储，也不会自动提供 attestation 服务、KMS、mTLS 身份或 Kubernetes TokenProvider 集成。

## 前置条件

- Helm 3.12 或更高版本。
- 满足 Chart `kubeVersion` 约束的 Kubernetes 集群。
- 仓库 workflow 已发布的三个容器镜像，或为三个镜像配置自定义 repository。
- Authority Ed25519 签名私钥、每个 node-agent identity 对应的身份私钥，以及正常 signer 路径使用的 Infisical KMS token。

## 安装

请在 Chart 外部创建所需 Secret。敏感值不会放入默认 `values.yaml` 或生成的 ConfigMap：

```bash
kubectl create namespace issuance
kubectl -n issuance create secret generic kci-authority-signing-key \
  --from-file=eaa-private-key.pem=./eaa-private-key.pem
kubectl -n issuance create secret generic kci-signer-kms \
  --from-file=token=./infisical-kms-token
kubectl -n issuance create secret generic kci-node-identity \
  --from-file=worker-1.pem=./worker-1.pem
```

在私有 values 文件中设置 Secret 名称，以及真实的 policy、registration、generation、KMS 和 attestation 参数：

```yaml
authority:
  signingKey:
    secretName: kci-authority-signing-key
  config:
    cluster_id: cluster-1
    issuer: https://issuer.example
    policy_version: sa-policy-v1
    signing_key_id: eaa-2026-01
    registrations: []

signer:
  kms:
    endpoint: https://infisical.example
    authToken:
      secretName: kci-signer-kms
  config:
    eaa_keys:
      eaa-2026-01: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
    key_generations:
      - generation: generation-1
        key_id: jwt-2026-01
        key_ref: REPLACE_INFISICAL_KMS_KEY_UUID
        public_key: REPLACE_BASE64_DER_PUBLIC_KEY
        algorithm: RS256
        state: Active

nodeAgent:
  identityKey:
    secretName: kci-node-identity
  config:
    identity: worker-1
    attestation_endpoint: https://attestor.example/v1/attest
    attestation_identity: node-attestor-1
    attestation_public_key: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
```

安装或升级 release：

```bash
helm upgrade --install kci ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --values ./values-private.yaml
```

在受控测试集群中，也可以让 Chart 管理 Secret：

```bash
helm upgrade --install kci ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --set authority.signingKey.create=true \
  --set-file authority.signingKey.value=./eaa-private-key.pem \
  --set signer.kms.authToken.create=true \
  --set-file signer.kms.authToken.value=./infisical-kms-token \
  --set nodeAgent.identityKey.create=true \
  --set-file nodeAgent.identityKey.value=./worker-1.pem
```

生产环境请为 authority 和 signer 启用 TLS，引用预先创建的
`kubernetes.io/tls` Secret，并确保证书包含对应的 Service DNS 名称。默认 HTTP listener 只适用于隔离开发环境。node-agent 默认使用 hostPath 支持的 Unix socket；请将 `nodeAgent.socket.hostPath` 设置为批准的节点路径，并把该路径接入实际消费此 socket 的本地 Kubernetes 组件。

## 生产集群与外部 issuance 集群分离部署

推荐的生产拓扑是：把 issuance 服务放在独立的 issuance 集群中，在每个业务集群中运行 node-agent DaemonSet：

```text
业务集群                                  issuance 集群
sa-node-agent DaemonSet -- HTTPS -->      sa-authority Service
                                      \--> sa-signer Service
```

使用两个 Helm release。issuance 集群的 values 关闭 DaemonSet：

```yaml
# values-issuance.yaml，在 issuance 集群执行
authority:
  enabled: true
  tls:
    enabled: true
    secretName: sa-authority-tls
  signingKey:
    secretName: sa-authority-signing-key

signer:
  enabled: true
  tls:
    enabled: true
    secretName: sa-signer-tls
  kms:
    authToken:
      secretName: sa-signer-kms

nodeAgent:
  enabled: false
```

在 issuance 集群创建 authority 签名私钥、signer KMS token 和 TLS Secret 后安装：

```bash
helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --values ./values-issuance.yaml
```

业务集群的 values 关闭两个服务 Deployment，并覆盖自动生成的集群内 endpoint：

```yaml
# values-node-agent.yaml，在业务集群执行
authority:
  enabled: false

signer:
  enabled: false

nodeAgent:
  enabled: true
  config:
    authority_endpoint: https://sa-authority.issuance.example/v1/grants
    signer_endpoint: https://sa-signer.issuance.example/v1/sign
    identity: worker-1
    attestation_endpoint: https://attestor.workload.example/v1/attest
    attestation_identity: node-attestor-1
    attestation_public_key: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
  identityKey:
    secretName: sa-node-identity
```

在业务集群创建 node identity Secret 后安装：

```bash
helm upgrade --install kci-node-agent ./charts/k8s-credential-issuance \
  --namespace kube-system \
  --values ./values-node-agent.yaml
```

如果只是同一集群中的不同 Namespace，可以使用 issuance Service 的完整 DNS 名称，例如
`https://kci-issuance-k8s-credential-issuance-authority.issuance.svc.cluster.local:9441/v1/grants`。
如果是不同集群，ClusterIP Service 和 `*.svc.cluster.local` 名称不可路由；请通过内部 LoadBalancer、Gateway 或等价网络路径发布稳定的私有 DNS，并在 node-agent values 中使用这些名称。Chart 不会创建跨集群网络路径。

当前二进制和 Chart 只提供 server-side TLS；客户端证书、自定义 CA bundle 和完整 mTLS 身份 provisioning 必须由外围平台提供。还需要注意，一个 node-agent DaemonSet 当前会在所有节点挂载同一份配置的 `identity` 和 identity-key Secret；如果需要每节点独立身份，需要拆分 node pool/release，或增加节点本地的身份注入机制。

## 配置与扩缩容

- Authority 和 signer 默认使用独立 PVC 保存状态。使用仓库内置文件型 store 时请保持单副本；扩容前必须替换为支持事务的共享 backend。
- `authority.config.registrations`、`signer.config.key_generations` 和 `nodeAgent.config` 会直接映射到二进制读取的 JSON 配置；Chart 会补充挂载文件路径和集群内 Service URL。
- `signer.allowLocalKeyProvider` 和 `nodeAgent.allowStaticBindings` 是仅用于开发的逃生开关，生产环境应保持关闭。
- 当前代码树没有 `ca-*` 或 `etcd-*` 命令二进制，因此本 Chart 不会为这些计划中的组件创建工作负载。

协议与信任边界说明见 [ServiceAccount 部署参考](../../docs/deployment/sa-issuance.zh-CN.md)。

## 验证 Chart

```bash
helm lint ./charts/k8s-credential-issuance
helm template kci ./charts/k8s-credential-issuance --namespace issuance
```
