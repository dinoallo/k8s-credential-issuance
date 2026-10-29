// Package core exposes the common issuance contracts. Concrete implementations
// live in the focused subpackages under this directory.
package core

import (
	"context"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
)

type Request = pipeline.Request
type Binding = pipeline.Binding
type Plugin = pipeline.Plugin
type Engine = pipeline.Engine
type EngineConfig = pipeline.Config

type IssuancePlugin interface {
	Domain() v1.Domain
	Canonicalize(context.Context, Request) (Binding, error)
	ValidateBinding(context.Context, v1.Grant, Binding) error
	Prepare(context.Context, v1.Grant, Binding, string) (kms.SigningIntent, error)
	Finalize(context.Context, v1.Grant, Binding, kms.Artifact) ([]byte, error)
}

func New(config EngineConfig) (*Engine, error) {
	return pipeline.New(config)
}
