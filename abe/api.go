package abe

import (
	"time"
)

type PublicABEAPI struct {
	abeService *ABEService
}

type Envelope struct {
	Header []byte `json:"header"`
	Body   []byte `json:"body"`
}

func NewPublicABEAPI(abeService *ABEService) *PublicABEAPI {
	return &PublicABEAPI{abeService}
}

func (s *PublicABEAPI) Hi() string {
	return time.Now().Format(time.RFC850)
}

/* func (s *PublicABEAPI) Setup(attr []string) (interface{}, error) {
	// Convert attr from []string to []Attribute
	labels := gpsw06.NewAttributes(attr)

	// Construct attribute space
	algo, err := gpsw06.NewGPSW06(labels)
	if err != nil {
		return nil, err
	}

	// Generate public key and master secret key
	pk, msk := algo.Setup()
	// TODO: Serialize keys
	return map[string]interface{}{
		"pk":  "",
		"msk": "",
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

func (s *PublicABEAPI) Encrypt(plaintext string, attr []string, msk string) (string, error) {
	// TODO: De-serialize msk
	// TODO: Convert []string to map[int]struct{}

	algo, _ := gpsw06.NewGPSW06()
	sessionKey := gpsw06.NewMessage().Rand()

	header, err := algo.Encrypt(sessionKey, _, msk)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aesgcm_encrypt(sessionKey.Marshal(), []byte(plaintext))
	if err != nil {
		return nil, err
	}

	return json.Marshal(Envelope{header, ciphertext})
}

func (s *PublicABEAPI) KeyGen(tree, msk string) (string, error) {
	// TODO: De-serialize tree
	// TODO: De-serialize msk

	algo, _ := gpsw06.NewGPSW06()
	dk, err := algo.KeyGen(_, _)
	if err != nil {
		return nil, err
	}

	// TODO: Serialize dk
	return dk, nil
}

func (s *PublicABEAPI) Decrypt(ciphertext, decryptKey string) (string, error) {
	// TODO: Deserialize decryptKey

	var envelope = Envelope{}
	if err := json.Unmarshal(ciphertext, &envelope); err != nil {
		return nil, err
	} else if len(envelope.Header) == 0 || len(envelope.Body) == 0 {
		return nil, errors.New("Invalid ciphertext")
	}

	algo, _ := gpsw06.NewGPSW06()
	sessionKey, err := algo.Decrypt(envelope.Header, _)

	plaintext, err := aesgcm_decrypt(sessionKey, envelope.Body)
	if err != nil {
		return nil, err
	}
	return string(plaintext), nil
} */
