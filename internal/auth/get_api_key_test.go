package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Define a estrutura para os casos de teste
	tests := []struct {
		name          string
		setupHeaders  func() http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Sucesso com ApiKey válida",
			setupHeaders: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey token_secreto_123")
				return h
			},
			expectedKey:   "token_secreto_123",
			expectedError: nil,
		},
		{
			name: "Erro quando o header Authorization está ausente",
			setupHeaders: func() http.Header {
				return http.Header{}
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Erro quando usa Bearer em vez de ApiKey",
			setupHeaders: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer outro_token")
				return h
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Erro quando o formato está malformado (sem espaço)",
			setupHeaders: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKeyTokenSemEspaco")
				return h
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	// Executa cada caso de teste
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.setupHeaders()
			
			gotKey, gotErr := GetAPIKey(headers)

			// Valida o retorno da chave
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() chave obtida = %v, esperada = %v", gotKey, tt.expectedKey)
			}

			// Valida o retorno do erro
			if (gotErr == nil && tt.expectedError != nil) || (gotErr != nil && tt.expectedError == nil) {
				t.Errorf("GetAPIKey() erro obtido = %v, esperado = %v", gotErr, tt.expectedError)
			} else if gotErr != nil && tt.expectedError != nil && gotErr.Error() != tt.expectedError.Error() {
				t.Errorf("GetAPIKey() mensagem de erro obtida = %v, esperada = %v", gotErr.Error(), tt.expectedError.Error())
			}
		})
	}
}
