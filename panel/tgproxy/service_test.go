package tgproxy

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestDeriveBridgeToken(t *testing.T) {
	domain := "tg.example.com"
	secret := "d41d8cd98f00b204e9800998ecf8427e"
	tok := DeriveBridgeToken(domain, secret)
	// Capability is 32 raw bytes base64url encoded without padding => 43 chars
	if len(tok) != 43 {
		t.Fatalf("expected 43 base64url chars, got %d: %s", len(tok), tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("invalid base64url string: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32 decoded bytes, got %d", len(raw))
	}
}

func TestServiceLinks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tgproxy-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	svc := NewService(tmpDir, "87.228.113.192")
	sec := "0123456789abcdef0123456789abcdef"
	cfg := Config{
		Enabled:    true,
		Port:       8443,
		Secret:     sec,
		TLSDomain:  "ya.ru",
		Upstream:   "direct",
		WebEnabled: true,
		WebDomain:  "tg.example.com",
		WebPort:    8085,
	}

	svc.config = cfg
	st := svc.GetStatus("87.228.113.192")

	if !strings.HasPrefix(st.MTProtoLink, "tg://proxy?server=87.228.113.192&port=8443&secret=ee0123456789abcdef0123456789abcdef") {
		t.Fatalf("unexpected mtproto link: %s", st.MTProtoLink)
	}
	// ya.ru in hex is 79612e7275
	if !strings.HasSuffix(st.MTProtoLink, "79612e7275") {
		t.Fatalf("mtproto link missing domain hex: %s", st.MTProtoLink)
	}

	if !strings.HasPrefix(st.WebLink, "https://tg.example.com/?bridge=") {
		t.Fatalf("unexpected web link: %s", st.WebLink)
	}
	if len(st.BridgeToken) != 43 {
		t.Fatalf("expected 43 char bridge token, got %q", st.BridgeToken)
	}
}
