package jwt

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func TestGenerate(t *testing.T) {
	type args struct {
		h      *Header
		p      *Payload
		cp     *CustomPayload
		sum    HashSumFunction
		secret []byte
	}
	secret := []byte("fooooo3")
	header := Header{Typ: "JWT", Alg: "SHA512"}
	payload := Payload{Iss: "Test3"}
	sum := func(b []byte) []byte {
		n := sha512.Sum512(b)
		return n[:]
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "test Generate",
			args:    args{h: &header, p: &payload, cp: nil, sum: sum, secret: secret},
			wantErr: false,
		},
		{
			name:    "test Generate",
			args:    args{h: &header, p: nil, cp: nil, sum: sum, secret: secret},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Generate(tt.args.h, tt.args.p, tt.args.cp, tt.args.sum, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_isValid(t *testing.T) {
	secret := []byte("fooooo3")
	header := Header{Typ: "JWT", Alg: "SHA512"}
	Payload := Payload{Iss: "Test3"}

	// Adaptor needed to keep the Generate function agnostic towards the sum function that is passed
	sum := func(b []byte) []byte {
		n := sha512.Sum512(b)
		return n[:]
	}

	hash, err := Generate(&header, &Payload, nil, sum, secret)
	if err != nil {
		panic(err.Error())
	}

	type args struct {
		jwt    []byte
		secret []byte
		sum    HashSumFunction
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test isValid",
			args: args{
				jwt: hash, secret: secret, sum: sum,
			},
			want: true,
		},
		{
			name: "test isValid",
			args: args{
				jwt: bytes.Join([][]byte{[]byte("fooooooo3"), hash}, []byte("")), secret: secret, sum: sum,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValid(tt.args.jwt, tt.args.secret, tt.args.sum); got != tt.want {
				t.Errorf("isValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
