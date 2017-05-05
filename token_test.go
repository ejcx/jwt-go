package jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestSignatureValidation(t *testing.T) {
	hmacSampleSecret := []byte("notagoodsecret")
	token := NewWithClaims(SigningMethodHS256, MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Create a jwt.
	tokenString, err := token.SignedString(hmacSampleSecret)

	if err != nil {
		t.Errorf("Could not sign token: %s", err)
	}

	// Keep track of how many unique JWTs we verify. We should only ever
	// verify, at maximum, 1 JWT.
	successCount := 0
	fmt.Printf("Real JWT is: %s\n", tokenString)

	alphabetics := "abcdefghijklmnopqrstuvwxyz"
	for i := 0; i < 25; i++ {
		// Lop off the final character of the JWT signature and replace it with
		// the next one from our list.
		tokenString = tokenString[:len(tokenString)-1] + string(alphabetics[i])

		// This is literally the Example verification code, copied and pasted
		parsedToken, err := Parse(tokenString, func(token *Token) (interface{}, error) {
			if _, ok := token.Method.(*SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return hmacSampleSecret, nil
		})

		// This does the meat of the verification. If we verify a JWT print it out
		// increment successCount, and if we verify more than 1 JWT ever then we
		// have successfully modified the signature and verified it.
		if _, ok := parsedToken.Claims.(MapClaims); ok && parsedToken.Valid {
			fmt.Printf("We verified this JWT: %s\n", tokenString)
			successCount++
			if successCount > 1 {
				t.Errorf("We verified this JWT with multiple different final chars: %s", err)
				return
			}
		}
	}

}
