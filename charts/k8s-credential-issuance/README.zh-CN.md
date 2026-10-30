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
