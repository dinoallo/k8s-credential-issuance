package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

type configFile struct {
	ClusterID             string                `json:"cluster_id"`
	Issuer                string                `json:"issuer"`
	PolicyVersion         string                `json:"policy_version"`
	EAAKeys               map[string]string     `json:"eaa_keys"`
	KMSEndpoint           string                `json:"kms_endpoint,omitempty"`
	KMSProvider           string                `json:"kms_provider,omitempty"`
	KMSAuthTokenFile      string                `json:"kms_auth_token_file,omitempty"`
	RevocationEndpoint    string                `json:"revocation_endpoint,omitempty"`
	AllowLegacyTokenGrant bool                  `json:"allow_legacy_token_grant,omitempty"`
	ReplayStateFile       string                `json:"replay_state_file"`
	LedgerStateFile       string                `json:"ledger_state_file"`
	MaxTokenLifetimeSecs  int64                 `json:"max_token_lifetime_seconds"`
	KeyGenerations        []generation.Metadata `json:"key_generations"`
	LocalKeyFiles         map[string]string     `json:"local_key_files,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "SA signer JSON configuration file")
	listenAddress := flag.String("listen-address", "127.0.0.1:9444", "HTTP or HTTPS listen address")
	tlsCertFile := flag.String("tls-cert-file", "", "TLS serving certificate")
	tlsKeyFile := flag.String("tls-key-file", "", "TLS serving private key")
	allowLocal := flag.Bool("allow-local-key-provider", false, "allow the development-only in-process private-key backend")
	flag.Parse()
	if *configPath == "" {
		fatal(fmt.Errorf("--config is required"))
	}
	if err := run(*configPath, *listenAddress, *tlsCertFile, *tlsKeyFile, *allowLocal); err != nil {
		fatal(err)
	}
}

func run(configPath, listenAddress, tlsCertFile, tlsKeyFile string, allowLocal bool) error {
	config, baseDir, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	registry, err := generation.NewRegistry(config.KeyGenerations)
	if err != nil {
		return err
	}
	active, err := registry.Active()
	if err != nil {
		return err
	}
	policies := make([]kms.Policy, 0, len(config.KeyGenerations))
	for _, metadata := range config.KeyGenerations {
		policies = append(policies, kms.Policy{Domain: "sa", Purpose: kms.PurposeServiceAccountJWT, Generation: metadata.Generation, KeyID: metadata.KeyID, KeyRef: metadata.KeyRef, PublicKey: metadata.PublicKey, Algorithm: metadata.Algorithm})
	}
	var backend kms.Backend
	if config.KMSEndpoint != "" {
		if allowLocal {
			return fmt.Errorf("--allow-local-key-provider cannot be combined with kms_endpoint")
		}
		switch strings.ToLower(config.KMSProvider) {
		case "", "http":
			backend = &kms.HTTPBackend{Endpoint: config.KMSEndpoint, HTTPClient: &http.Client{Timeout: 15 * time.Second}}
		case "infisical":
			if config.KMSAuthTokenFile == "" {
				return fmt.Errorf("kms_auth_token_file is required for the Infisical KMS provider")
			}
			tokenData, err := os.ReadFile(resolvePath(baseDir, config.KMSAuthTokenFile))
			if err != nil {
				return fmt.Errorf("read Infisical KMS token: %w", err)
			}
			token := strings.TrimSpace(string(tokenData))
			if token == "" {
				return fmt.Errorf("Infisical KMS token file is empty")
			}
			client, err := infisicalapi.NewClient(config.KMSEndpoint, token, &http.Client{Timeout: 15 * time.Second})
			if err != nil {
				return err
			}
			backend, err = kms.NewInfisicalBackend(client)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported kms_provider %q", config.KMSProvider)
		}
	} else {
		if !allowLocal {
			return fmt.Errorf("kms_endpoint is required; use --allow-local-key-provider only for isolated development")
		}
		privateKeys := make(map[string]crypto.PrivateKey, len(config.KeyGenerations))
		for _, metadata := range config.KeyGenerations {
			path, ok := config.LocalKeyFiles[metadata.Generation]
			if !ok {
				return fmt.Errorf("local key file for generation %q is missing", metadata.Generation)
			}
			data, err := os.ReadFile(resolvePath(baseDir, path))
			if err != nil {
				return err
			}
			key, err := kms.ParsePrivateKeyPEM(data)
			if err != nil {
				return fmt.Errorf("parse local key for generation %q: %w", metadata.Generation, err)
			}
			privateKeys[metadata.Generation] = key
		}
		backend, err = kms.NewLocalJWTBackend(policies, privateKeys)
		if err != nil {
			return err
		}
	}
	provider, err := kms.NewProvider(backend, registry, policies)
	if err != nil {
		return err
	}
	ledgerPath := config.LedgerStateFile
	if ledgerPath == "" {
		ledgerPath = config.ReplayStateFile
	}
	ledgerStore, err := ledger.NewFileStore(resolvePath(baseDir, ledgerPath))
	if err != nil {
		return err
	}
	plugin, err := sadomain.NewPlugin(sadomain.Config{ClusterID: config.ClusterID, Issuer: config.Issuer, PolicyVersion: config.PolicyVersion, DefaultKeyID: active.KeyID, DefaultAlgorithm: active.Algorithm, MaxTokenLifetime: time.Duration(config.MaxTokenLifetimeSecs) * time.Second})
	if err != nil {
		return err
	}
	var revocations pipeline.RevocationChecker
	if config.RevocationEndpoint != "" {
		revocations, err = sadomain.NewRevocationClient(config.RevocationEndpoint, nil)
		if err != nil {
			return err
		}
	}
	publicKeys := make(map[string]ed25519.PublicKey, len(config.EAAKeys))
	for keyID, encoded := range config.EAAKeys {
		key, err := identity.DecodePublicKey(encoded)
		if err != nil {
			return fmt.Errorf("decode EAA public key %q: %w", keyID, err)
		}
		publicKeys[keyID] = key
	}
	var grantVerifier pipeline.GrantVerifier
	if config.AllowLegacyTokenGrant {
		grantVerifier = sadomain.NewGrantVerifier(active.KeyID)
	}
	engine, err := pipeline.New(pipeline.Config{Domain: "sa", GrantKeys: publicKeys, GrantVerifier: grantVerifier, AllowLegacyRelay: config.AllowLegacyTokenGrant, Plugin: plugin, Ledger: ledgerStore, KMS: provider, Revocations: revocations, Audit: audit.NewJSONSink(os.Stdout)})
	if err != nil {
		return err
	}
	signer, err := sadomain.NewSigner(engine, provider)
	if err != nil {
		return err
	}
	if err := transport.RequireTLSForNonLoopback(listenAddress, tlsCertFile, tlsKeyFile); err != nil {
		return err
	}
	listener, cleanup, err := transport.Listen(listenAddress)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return transport.Run(ctx, listener, signer.Handler(), tlsCertFile, tlsKeyFile)
}

func loadConfig(path string) (configFile, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return configFile{}, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config configFile
	if err := decoder.Decode(&config); err != nil {
		return configFile{}, "", fmt.Errorf("decode signer configuration: %w", err)
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return configFile{}, "", err
	}
	return config, baseDir, nil
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
