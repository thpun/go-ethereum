package abe

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/thpun/ABE/bsw07"
	"time"
)

type PublicBSW07API struct {
	abeService *ABEService
}

func NewPublicBSW07API(abeService *ABEService) *PublicBSW07API {
	return &PublicBSW07API{abeService}
}

func (s *PublicBSW07API) Hi() string {
	return time.Now().Format(time.RFC850)
}

func (s *PublicBSW07API) Setup() (interface{}, error) {
	// Construct struct
	algo, err := bsw07.NewBSW07()
	if err != nil {
		return nil, err
	}

	// Generate public key and master key
	pk, msk := algo.Setup()

	// Serialize the keys
	pkStr, err := json.Marshal(pk)
	if err != nil {
		return nil, err
	}
	mskStr, err := json.Marshal(msk)
	if err != nil {
		return nil, err
	}

	return map[string]hexutil.Bytes{
		"pk":  pkStr,
		"msk": mskStr,
	}, nil
}

func (s *PublicBSW07API) Encrypt(plaintext hexutil.Bytes, tree string, pk hexutil.Bytes) (hexutil.Bytes, error) {
	// De-serialize tree
	_tree, err := bsw07.NodeFromJSON([]byte(tree))
	if err != nil {
		return nil, err
	}
	// De-serialize pk
	_pk := &bsw07.PublicKey{}
	if err := json.Unmarshal(pk, _pk); err != nil {
		return nil, err
	}

	algo, _ := bsw07.NewBSW07()
	sessionKey := bsw07.NewMessage().Rand()

	header, err := algo.Encrypt(_pk, sessionKey, _tree)
	if err != nil {
		return nil, err
	}
	headerStr, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aesgcm_encrypt(sessionKey.Marshal(), plaintext)
	if err != nil {
		return nil, err
	}

	return json.Marshal(Envelope{headerStr, ciphertext})
}

func (s *PublicBSW07API) Keygen(attr []string, msk hexutil.Bytes) (hexutil.Bytes, error) {
	// De-serialize msk
	_msk := &bsw07.MasterKey{}
	if err := json.Unmarshal(msk, _msk); err != nil {
		return nil, err
	}

	// Convert []string to map[string]struct{}
	_attr := make(map[string]struct{})
	for _, v := range attr {
		_attr[v] = struct{}{}
	}

	algo, _ := bsw07.NewBSW07()
	dk, err := algo.KeyGen(_msk, _attr)
	if err != nil {
		return nil, err
	}

	return json.Marshal(dk)
}

func (s *PublicBSW07API) Delegate(attr []string, dk hexutil.Bytes) (hexutil.Bytes, error) {
	// De-serialize dk
	_dk := &bsw07.DecryptKey{}
	if err := json.Unmarshal(dk, _dk); err != nil {
		return nil, err
	}

	// Convert []string to map[string]struct{}
	_attr := make(map[string]struct{})
	for _, v := range attr {
		_attr[v] = struct{}{}
	}

	algo, _ := bsw07.NewBSW07()
	lk, err := algo.Delegate(_dk, _attr)
	if err != nil {
		return nil, err
	}

	return json.Marshal(lk)
}

func (s *PublicBSW07API) Decrypt(ct, dk hexutil.Bytes) (hexutil.Bytes, error) {
	// De-serialize dk
	_dk := &bsw07.DecryptKey{}
	if err := json.Unmarshal(dk, _dk); err != nil {
		return nil, err
	}

	// De-serialize ct
	var envelope = Envelope{}
	if err := json.Unmarshal(ct, &envelope); err != nil {
		return nil, err
	} else if len(envelope.Header) == 0 || len(envelope.Body) == 0 {
		return nil, ErrInvalidCiphertext
	}

	algo, _ := bsw07.NewBSW07()
	// De-serialize envelope header, which is ABE ciphertext
	_ct := &bsw07.Ciphertext{}
	if err := json.Unmarshal(envelope.Header, _ct); err != nil {
		return nil, err
	}
	sessionKey, err := algo.Decrypt(_ct, _dk)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm_decrypt(sessionKey.Marshal(), envelope.Body)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
