package abe

import (
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
)

type ABEService struct{}

func New() (*ABEService, error) {
	return &ABEService{}, nil
}

// Protocols implements the node.Service interface.
func (service *ABEService) Protocols() []p2p.Protocol { return nil }

// APIs implements the node.Service interface.
func (serivce *ABEService) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "gpsw06",
			Version:   "1.0",
			Service:   NewPublicGPSW06API(serivce),
			Public:    true,
		},
	}
}

// Start implements the node.Service interface.
func (service *ABEService) Start(server *p2p.Server) error { return nil }

// Stop implements the node.Service interface.
func (service *ABEService) Stop() error { return nil }
