package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type Payload struct {
	Iss string
	Sub string
	Exp string
}

type CustomPayload map[string]string

type HashSumFunction func(b []byte) []byte

// Generate produces the jwt byte slice using the provided header, payload and hash function.
// Hashed signature is also base64 encoded.
func Generate(h *Header, p *Payload, cp *CustomPayload, sum HashSumFunction, secret []byte) ([]byte, error) {
	var err error
	var header []byte
	var payload []byte
	var hash []byte
	var headerDotPayload []byte
	header, err = json.Marshal(&h)
	if err != nil {
		return nil, err
	}
	if p != nil {
		payload, err = json.Marshal(&p)
	} else {
		payload, err = json.Marshal(&cp)
	}
	if err != nil || bytes.Compare(payload, []byte("null")) == 0 {
		return nil, fmt.Errorf("expected a valid payload")
	}
	headerb64 := []byte(base64.StdEncoding.EncodeToString(header))
	payloadb64 := []byte(base64.StdEncoding.EncodeToString(payload))
	headerDotPayload = bytes.Join([][]byte{headerb64, payloadb64}, []byte("."))
	signature := sum(bytes.Join([][]byte{headerDotPayload, secret}, []byte("")))
	hash = bytes.Join([][]byte{headerDotPayload, signature[:]}, []byte("."))
	return hash, nil
}

func IsValid(jwt []byte, secret []byte, sum HashSumFunction) bool {
	header, n, ok := bytes.Cut(jwt, []byte("."))
	if !ok {
		return false
	}
	payload, n2, ok := bytes.Cut(n, []byte("."))
	if !ok {
		return false
	}
	headerDotPayload := bytes.Join([][]byte{header, payload}, []byte("."))
	signature := sum(bytes.Join([][]byte{headerDotPayload, secret}, []byte("")))
	if bytes.Compare(signature[:], n2) != 0 {
		fmt.Println("expected " + string(signature[:]) + " to equal " + string(n2))
		return false
	}
	return true
}
