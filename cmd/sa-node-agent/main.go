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

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

type configFile struct {
	AuthorityEndpoint    string                          `json:"authority_endpoint"`
	SignerEndpoint       string                          `json:"signer_endpoint"`
	Identity             string                          `json:"identity"`
	IdentityKeyFile      string                          `json:"identity_key_file"`
	Bindings             map[string]signapi.TokenBinding `json:"bindings"`
	AttestationEndpoint  string                          `json:"attestation_endpoint,omitempty"`
	AttestationIdentity  string                          `json:"attestation_identity,omitempty"`
	AttestationPublicKey string                          `json:"attestation_public_key,omitempty"`
	AttestationCAFile    string                          `json:"attestation_ca_file,omitempty"`
	AttestationCertFile  string                          `json:"attestation_client_cert_file,omitempty"`
	AttestationKeyFile   string                          `json:"attestation_client_key_file,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "SA node-agent JSON configuration file")
	listenAddress := flag.String("listen-address", "unix:///var/run/sa-node-agent.sock", "HTTP, HTTPS, or Unix-socket listen address")
	tlsCertFile := flag.String("tls-cert-file", "", "TLS serving certificate for a TCP listener")
	tlsKeyFile := flag.String("tls-key-file", "", "TLS serving private key for a TCP listener")
	allowStaticBindings := flag.Bool("allow-static-bindings", false, "allow the development-only static bindings resolver")
	flag.Parse()
	if *configPath == "" {
		fatal(fmt.Errorf("--config is required"))
	}
	if err := run(*configPath, *listenAddress, *tlsCertFile, *tlsKeyFile, *allowStaticBindings); err != nil {
		fatal(err)
	}
}

func run(configPath, listenAddress, tlsCertFile, tlsKeyFile string, allowStaticBindings bool) error {
	config, baseDir, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(resolvePath(baseDir, config.IdentityKeyFile))
	if err != nil {
		return err
	}
	identityKey, err := identity.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return err
	}
	var resolver sadomain.BindingResolver
	switch {
	case config.AttestationEndpoint != "":
		if allowStaticBindings {
			return fmt.Errorf("--allow-static-bindings cannot be combined with attestation_endpoint")
		}
		if config.AttestationIdentity == "" || config.AttestationPublicKey == "" {
			return fmt.Errorf("attestation_identity and attestation_public_key are required with attestation_endpoint")
		}
		attestorKey, err := identity.DecodePublicKey(config.AttestationPublicKey)
		if err != nil {
			return fmt.Errorf("decode attestation public key: %w", err)
		}
		resolver, err = sadomain.NewRemoteAttestationResolver(sadomain.RemoteAttestationConfig{
			Endpoint:          config.AttestationEndpoint,
			Identity:          config.Identity,
			AttestorIdentity:  config.AttestationIdentity,
			AttestorPublicKey: attestorKey,
			TLSCAFile:         resolveOptionalPath(baseDir, config.AttestationCAFile),
			TLSCertFile:       resolveOptionalPath(baseDir, config.AttestationCertFile),
			TLSKeyFile:        resolveOptionalPath(baseDir, config.AttestationKeyFile),
		})
		if err != nil {
			return err
		}
	case allowStaticBindings:
		if len(config.Bindings) == 0 {
			return fmt.Errorf("static bindings are empty")
		}
		resolver = sadomain.StaticBindingResolver{Bindings: config.Bindings}
	default:
		return fmt.Errorf("attestation_endpoint is required; use --allow-static-bindings only for development")
	}
	provider, err := sadomain.NewProvider(sadomain.AgentConfig{AuthorityEndpoint: config.AuthorityEndpoint, SignerEndpoint: config.SignerEndpoint, Identity: config.Identity, IdentityKey: identityKey, Resolver: resolver})
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
	return transport.Run(ctx, listener, provider.Handler(), tlsCertFile, tlsKeyFile)
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
		return configFile{}, "", fmt.Errorf("decode node-agent configuration: %w", err)
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

func resolveOptionalPath(baseDir, path string) string {
	if path == "" {
		return ""
	}
	return resolvePath(baseDir, path)
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
