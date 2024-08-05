package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey",
			headers: http.Header{
				"Authorization": []string{"Bearer some_token"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Missing Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey some_api_key"},
			},
			expectedKey:   "some_api_key",
			expectedError: nil,
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)
			if key != tt.expectedKey {
				t.Errorf("test %d: expected key %q, got %q", idx+1, tt.expectedKey, key)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("test %d: expected error %q, got %q", idx+1, tt.expectedError, err)
			}
		})
	}
}
