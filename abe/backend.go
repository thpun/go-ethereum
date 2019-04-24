package abe

import "github.com/jpmorganchase/quorum/rpc"

type ABEService struct{}

func New() (*ABEService, error) {
	return &ABEService{}, nil
}

func (serivce *ABEService) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "abe",
			Version:   "1.0",
			Service:   NewPublicABEAPI{serivce},
			Public:    true,
		},
	}
}
