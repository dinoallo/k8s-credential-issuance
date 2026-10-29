package etcd_test

import (
	"testing"

	etcdomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/etcd"
)

func TestQuorumRotationRequiresOverlapAndPreservesMajority(t *testing.T) {
	state := etcdomain.QuorumState{Members: []etcdomain.PeerState{{ID: "m1", Healthy: true}, {ID: "m2", Healthy: true}, {ID: "m3", Healthy: true}}, TrustOverlapReady: true}
	if err := etcdomain.ValidateQuorum(state); err != nil {
		t.Fatal(err)
	}
	if err := etcdomain.CanRotatePeer(state); err != nil {
		t.Fatal(err)
	}
	state.Members[1].Healthy = false
	if err := etcdomain.CanRotatePeer(state); err == nil {
		t.Fatal("rotation was allowed below quorum")
	}
	state.Members[1].Healthy = true
	state.TrustOverlapReady = false
	if err := etcdomain.ValidateQuorum(state); err == nil {
		t.Fatal("rotation was allowed without overlap trust")
	}
}
