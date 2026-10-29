package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/sa"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
)

type configFile struct {
	ClusterID            string                    `json:"cluster_id"`
	Issuer               string                    `json:"issuer"`
	PolicyVersion        string                    `json:"policy_version"`
	GrantFormat          string                    `json:"grant_format,omitempty"`
	SigningKeyID         string                    `json:"signing_key_id"`
	SigningKeyFile       string                    `json:"signing_key_file"`
	ProofReplayStateFile string                    `json:"proof_replay_state_file"`
	ReplayStateFile      string                    `json:"replay_state_file,omitempty"`
	GrantLedgerFile      string                    `json:"grant_ledger_file"`
	MaxTokenLifetimeSecs int64                     `json:"max_token_lifetime_seconds"`
	Registrations        []sa.WorkloadRegistration `json:"registrations"`
}

func main() {
	configPath := flag.String("config", "", "SA authority JSON configuration file")
	listenAddress := flag.String("listen-address", "127.0.0.1:9441", "HTTP or HTTPS listen address")
	tlsCertFile := flag.String("tls-cert-file", "", "TLS serving certificate")
	tlsKeyFile := flag.String("tls-key-file", "", "TLS serving private key")
	flag.Parse()
	if *configPath == "" {
		fatal(fmt.Errorf("--config is required"))
	}
	if err := run(*configPath, *listenAddress, *tlsCertFile, *tlsKeyFile); err != nil {
		fatal(err)
	}
}

func run(configPath, listenAddress, tlsCertFile, tlsKeyFile string) error {
	config, baseDir, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	privateKeyData, err := os.ReadFile(resolvePath(baseDir, config.SigningKeyFile))
	if err != nil {
		return fmt.Errorf("read authority signing key: %w", err)
	}
	privateKey, err := identity.ParsePrivateKeyPEM(privateKeyData)
	if err != nil {
		return err
	}
	registrations := sa.NewMemoryRegistrationStore()
	for _, registration := range config.Registrations {
		if err := registrations.Register(context.Background(), registration); err != nil {
			return err
		}
	}
	proofReplayPath := config.ProofReplayStateFile
	if proofReplayPath == "" {
		proofReplayPath = config.ReplayStateFile
	}
	proofReplay, err := replay.NewFileStore(resolvePath(baseDir, proofReplayPath), nil)
	if err != nil {
		return err
	}
	grants, err := sa.NewFileGrantLedger(resolvePath(baseDir, config.GrantLedgerFile))
	if err != nil {
		return err
	}
	maxLifetime := time.Duration(config.MaxTokenLifetimeSecs) * time.Second
	if maxLifetime <= 0 {
		maxLifetime = time.Hour
	}
	authority, err := sa.New(sa.Config{ClusterID: config.ClusterID, Issuer: config.Issuer, PolicyVersion: config.PolicyVersion, KeyID: config.SigningKeyID, PrivateKey: privateKey, GrantFormat: config.GrantFormat, Registrations: registrations, ProofReplay: proofReplay, Grants: grants, Audit: audit.NewJSONSink(os.Stdout), MaxTokenLifetime: maxLifetime})
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
	return transport.Run(ctx, listener, authority.Handler(), tlsCertFile, tlsKeyFile)
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
		return configFile{}, "", fmt.Errorf("decode authority configuration: %w", err)
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
