package abe

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Envelope struct {
	Header hexutil.Bytes `json:"header"`
	Body   hexutil.Bytes `json:"body"`
}

func aesgcm_encrypt(_key, _plaintext []byte) ([]byte, error) {
	key := _key[0:32]
	nonce := _key[32:44]
	data := _key[44:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, _plaintext, data), nil
}

func aesgcm_decrypt(_key, _ciphertext []byte) ([]byte, error) {
	key := _key[0:32]
	nonce := _key[32:44]
	data := _key[44:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, _ciphertext, data)
}
