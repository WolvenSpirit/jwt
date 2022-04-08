[![jwt](https://github.com/WolvenSpirit/jwt/actions/workflows/go.yml/badge.svg)](https://github.com/WolvenSpirit/jwt/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/WolvenSpirit/jwt/branch/main/graph/badge.svg?token=jUVFKX7ru4)](https://codecov.io/gh/WolvenSpirit/jwt)
# JWT
### JSON Web Token minimal implementation 

```go
// Example

func main() {
	secret := []byte("fooooo3")
	header := jwt.Header{Typ: "JWT", Alg: "SHA512"}
	payload := jwt.Payload{Iss: "TheIssuer"}

	// Adaptor needed to keep the Generate function agnostic towards the sum function that is passed
	sum := func(b []byte) []byte {
		n := sha512.Sum512(b)
		return n[:]
	}

	hash, err := jwt.Generate(&header, &payload, nil, sum, secret)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("%t", jwt.isValid(hash, secret, sum))
}
```
