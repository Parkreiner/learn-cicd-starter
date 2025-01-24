package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("Errors if auth header is missing", func(t *testing.T) {
		res, err := GetAPIKey(http.Header{})
		if err != ErrNoAuthHeaderIncluded {
			t.Error("Did not receive expected error value")
		}
		if res != "" {
			t.Error("Parsed token even when invalid")
		}
	})
	t.Run("Errors if bearer token is malformed", func(t *testing.T) {
		inputs := []http.Header{
			{
				"Authorization": []string{""},
			},
			{
				"Authorization": []string{"ApiKey"},
			},
			{
				"Authorization": []string{"apikey"},
			},
			{
				"Authorization": []string{"Bearer cool"},
			},
		}
		for _, i := range inputs {
			res, err := GetAPIKey(i)
			header := i.Get("Authorization")
			if err == nil {
				t.Errorf("Did not receive error for malformed header '%s'", header)
			}
			if res != "" {
				t.Errorf("Parsed token even when invalid for header '%s'", header)
			}
		}
	})
	t.Run("Parses token if it is present and valid", func(t *testing.T) {
		tokenValue := "Cool"
		res, err := GetAPIKey(http.Header{
			"Authorization": []string{"ApiKey " + tokenValue},
		})
		if err != nil {
			t.Error("Failed to parse token")
		}
		if res != tokenValue {
			t.Errorf("Wanted parsed token '%s' but got '%s'", tokenValue, res)
		}
	})
}
