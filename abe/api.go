package abe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/thpun/ABE/gpsw06"
	"time"
)

type PublicABEAPI struct {
	abeService *ABEService
}

type Envelope struct {
	Header hexutil.Bytes `json:"header"`
	Body   hexutil.Bytes `json:"body"`
}

func NewPublicABEAPI(abeService *ABEService) *PublicABEAPI {
	return &PublicABEAPI{abeService}
}

func (s *PublicABEAPI) Hi() string {
	return time.Now().Format(time.RFC850)
}

func (s *PublicABEAPI) Setup(attr []string) (interface{}, error) {
	// Convert attr from []string to []Attribute
	labels := gpsw06.NewAttributes(attr)

	// Construct attribute space
	algo, err := gpsw06.NewGPSW06(labels)
	if err != nil {
		return nil, err
	}

	// Generate public key and master secret key
	pk, msk := algo.Setup()

	// Serialize the keys
	pkStr, err := pk.Marshal()
	if err != nil {
		return nil, err
	}
	mskStr, err := msk.Marshal()
	if err != nil {
		return nil, err
	}

	return map[string]hexutil.Bytes{
		"pk":  pkStr,
		"msk": mskStr,
	}, nil
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

func (s *PublicABEAPI) Encrypt(plaintext hexutil.Bytes, attr []int, pk hexutil.Bytes) (hexutil.Bytes, error) {
	//  De-serialize msk
	_pk := gpsw06.PublicKey{}
	if _, err := _pk.Unmarshal(pk); err != nil {
		return nil, err
	}

	// Convert []string to map[int]struct{}
	_attr := make(map[int]struct{})
	for _, v := range attr {
		_attr[v] = struct{}{}
	}

	algo, _ := gpsw06.NewGPSW06(nil)
	sessionKey := gpsw06.NewMessage().Rand()

	header, err := algo.Encrypt(sessionKey, _attr, &_pk)
	if err != nil {
		return nil, err
	}

	headerStr, err := header.Marshal()
	if err != nil {
		return nil, err
	}

	ciphertext, err := aesgcm_encrypt(sessionKey.Marshal(), plaintext)
	if err != nil {
		return nil, err
	}

	return json.Marshal(Envelope{headerStr, ciphertext})
}

func (s *PublicABEAPI) Keygen(tree string, msk hexutil.Bytes) (hexutil.Bytes, error) {
	// De-serialize tree
	_tree, err := gpsw06.NodeFromJSON([]byte(tree))
	if err != nil {
		return nil, err
	}
	// De-serialize msk
	_msk := gpsw06.MasterKey{}
	if _, err := _msk.Unmarshal(msk); err != nil {
		return nil, err
	}

	algo, _ := gpsw06.NewGPSW06(nil)
	dk, err := algo.KeyGen(_tree, &_msk)
	if err != nil {
		return nil, err
	}

	// Serialize dk
	return dk.Marshal()
}

func (s *PublicABEAPI) Decrypt(ciphertext, decryptKey hexutil.Bytes) (hexutil.Bytes, error) {
	// Deserialize decryptKey
	dk := gpsw06.DecryptKey{}
	if _, err := dk.Unmarshal(decryptKey); err != nil {
		return nil, err
	}

	var envelope = Envelope{}
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		return nil, err
	} else if len(envelope.Header) == 0 || len(envelope.Body) == 0 {
		return nil, ErrInvalidCiphertext
	}

	algo, _ := gpsw06.NewGPSW06(nil)
	// Deserialize envelope header, which is ABE ciphertext
	ct := gpsw06.Ciphertext{}
	if _, err := ct.Unmarshal(envelope.Header); err != nil {
		return nil, err
	}
	sessionKey, err := algo.Decrypt(&ct, &dk)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm_decrypt(sessionKey.Marshal(), envelope.Body)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
