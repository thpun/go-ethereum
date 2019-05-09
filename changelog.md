# Changelog

* `params/version.go`
* `cmd/geth/misccmd.go`

    * Version number

* `abe/api.go`
* `abe/backend.go`
    * Implement interface of github.com/ethereum/go-ethereum/node.Service
    * RPC API for crypto operations
    * New `web3` namespace for crypto operations

* `cmd/geth/config.go`
    * Register ABE service to node stack
