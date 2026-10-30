// sa-attestor is the production Kubernetes-backed attestation service for
// ServiceAccount issuance. It only reads Pods and ServiceAccounts from the
// Kubernetes API and signs binding proofs with its own Ed25519 key.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	attestation "github.com/dinoallo/k8s-credential-issuance/internal/attestation/kubernetes"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
)

func main() {
	if err := run(parseFlags()); err != nil {
		fatal(err)
	}
}

type options struct {
	listenAddress    string
	tlsCertFile      string
	tlsKeyFile       string
	clientCAFile     string
	attestorIdentity string
	attestorKeyFile  string
	clusterID        string
	issuer           string
	tokenGeneration  string
	tokenKeyID       string
	defaultAudience  string
	maxTokenLifetime time.Duration
	kubeAPIServer    string
	kubeAPITokenFile string
	kubeAPICAFile    string
	printPublicKey   bool
}

func parseFlags() options {
	var result options
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.StringVar(&result.listenAddress, "listen-address", ":9445", "HTTPS or Unix-socket listen address")
	flagSet.StringVar(&result.tlsCertFile, "tls-cert-file", "", "TLS serving certificate for a TCP listener")
	flagSet.StringVar(&result.tlsKeyFile, "tls-key-file", "", "TLS serving private key for a TCP listener")
	flagSet.StringVar(&result.clientCAFile, "client-ca-file", "", "CA bundle used to verify node-agent client certificates")
	flagSet.StringVar(&result.attestorIdentity, "attestor-identity", "", "stable attestor identity")
	flagSet.StringVar(&result.attestorKeyFile, "attestor-key-file", "", "PKCS#8 Ed25519 attestor private key")
	flagSet.StringVar(&result.clusterID, "cluster-id", "", "issuance cluster ID")
	flagSet.StringVar(&result.issuer, "issuer", "", "ServiceAccount token issuer")
	flagSet.StringVar(&result.tokenGeneration, "token-generation", "", "active token key generation")
	flagSet.StringVar(&result.tokenKeyID, "token-key-id", "", "active token key ID")
	flagSet.StringVar(&result.defaultAudience, "default-audience", "", "default TokenRequest audience")
	flagSet.DurationVar(&result.maxTokenLifetime, "max-token-lifetime", time.Hour, "maximum attested token lifetime")
	flagSet.StringVar(&result.kubeAPIServer, "kube-api-server", "", "HTTPS Kubernetes API server URL; empty uses in-cluster discovery")
	flagSet.StringVar(&result.kubeAPITokenFile, "kube-api-token-file", "", "Kubernetes API bearer-token file; empty uses the projected in-cluster path")
	flagSet.StringVar(&result.kubeAPICAFile, "kube-api-ca-file", "", "Kubernetes API CA file; empty uses the projected in-cluster path")
	flagSet.BoolVar(&result.printPublicKey, "print-public-key", false, "print the attestor public key and exit")
	flagSet.Parse(os.Args[1:])
	return result
}

func run(options options) error {
	if options.attestorKeyFile == "" {
		return fmt.Errorf("--attestor-key-file is required")
	}
	attestorKey, err := identity.LoadPrivateKeyFile(options.attestorKeyFile)
	if err != nil {
		return fmt.Errorf("load attestor key: %w", err)
	}
	if options.printPublicKey {
		publicKey, ok := attestorKey.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("attestor key does not have an Ed25519 public key")
		}
		fmt.Println(identity.EncodePublicKey(publicKey))
		return nil
	}
	if options.attestorIdentity == "" || options.clusterID == "" || options.issuer == "" || options.tokenGeneration == "" || options.tokenKeyID == "" || options.defaultAudience == "" {
		return fmt.Errorf("--attestor-identity, --cluster-id, --issuer, --token-generation, --token-key-id, and --default-audience are required")
	}
	if options.maxTokenLifetime <= 0 {
		return fmt.Errorf("--max-token-lifetime must be positive")
	}

	kubeAPI, err := attestation.NewClient(attestation.ClientConfig{
		APIServer: options.kubeAPIServer,
		TokenFile: options.kubeAPITokenFile,
		CAFile:    options.kubeAPICAFile,
	})
	if err != nil {
		return fmt.Errorf("configure Kubernetes API client: %w", err)
	}
	authorizePeer, tlsConfig, err := serverSecurity(options)
	if err != nil {
		return err
	}
	service, err := attestation.NewService(attestation.Config{
		AttestorIdentity: options.attestorIdentity,
		AttestorKey:      attestorKey,
		ClusterID:        options.clusterID,
		Issuer:           options.issuer,
		TokenGeneration:  options.tokenGeneration,
		KeyID:            options.tokenKeyID,
		DefaultAudience:  options.defaultAudience,
		MaxTokenLifetime: options.maxTokenLifetime,
		API:              kubeAPI,
		AuthorizePeer:    authorizePeer,
	})
	if err != nil {
		return err
	}
	listener, cleanup, err := transport.Listen(options.listenAddress)
	if err != nil {
		return fmt.Errorf("listen for attestor: %w", err)
	}
	defer cleanup()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return transport.RunWithTLSConfig(ctx, listener, service.Handler(), tlsConfig)
}

func serverSecurity(options options) (attestation.PeerAuthorizer, *tls.Config, error) {
	if isUnixAddress(options.listenAddress) {
		if options.tlsCertFile != "" || options.tlsKeyFile != "" || options.clientCAFile != "" {
			return nil, nil, fmt.Errorf("TLS flags cannot be used with a Unix attestor socket")
		}
		return nil, nil, nil
	}
	if options.tlsCertFile == "" || options.tlsKeyFile == "" || options.clientCAFile == "" {
		return nil, nil, fmt.Errorf("TCP attestor listeners require --tls-cert-file, --tls-key-file, and --client-ca-file")
	}
	if err := transport.RequireTLSForNonLoopback(options.listenAddress, options.tlsCertFile, options.tlsKeyFile); err != nil {
		return nil, nil, err
	}
	tlsConfig, err := transport.NewMTLSConfig(options.tlsCertFile, options.tlsKeyFile, options.clientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("configure attestor mTLS: %w", err)
	}
	return attestation.RequireTLSClientIdentity, tlsConfig, nil
}

func isUnixAddress(address string) bool {
	return strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/")
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
