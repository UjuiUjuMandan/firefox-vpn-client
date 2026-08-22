package vpnclient

import "testing"

func TestNewFxaAPIErrorParsesErrno(t *testing.T) {
	apiErr := newFxaAPIError(400, []byte(`{"code":400,"errno":107,"message":"Invalid parameter: verificationMethod"}`))
	if apiErr.Errno != fxaErrnoInvalidParameter {
		t.Fatalf("expected errno %d, got %d", fxaErrnoInvalidParameter, apiErr.Errno)
	}

	plain := newFxaAPIError(500, []byte("boom"))
	if plain.Errno != 0 {
		t.Fatalf("expected errno 0 for non-JSON body, got %d", plain.Errno)
	}
}
