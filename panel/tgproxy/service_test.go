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

	if st.WebLink != "tg://webproxy?server=tg.example.com&port=443&secret=0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected web link: %s", st.WebLink)
	}
	if st.WebTmeLink != "https://t.me/webproxy?server=tg.example.com&port=443&secret=0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected web tme link: %s", st.WebTmeLink)
	}
	if !strings.HasPrefix(st.BridgeLink, "https://tg.example.com/?bridge=") {
		t.Fatalf("unexpected bridge link: %s", st.BridgeLink)
	}
	if len(st.BridgeToken) != 43 {
		t.Fatalf("expected 43 char bridge token, got %q", st.BridgeToken)
	}
}

func TestUserTelegram(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tgproxy-user-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	svc := NewService(tmpDir, "87.228.113.192")
	svc.config = Config{
		Enabled:    true,
		Port:       8443,
		Secret:     "0123456789abcdef0123456789abcdef",
		TLSDomain:  "ya.ru",
		WebEnabled: true,
		WebDomain:  "tg.example.com",
		WebPort:    8085,
	}

	// 1. Auto-generate user config on GetUser
	u1, err := svc.GetUser("user1", "87.228.113.192")
	if err != nil {
		t.Fatalf("GetUser error: %v", err)
	}
	if len(u1.Secret) != 32 {
		t.Fatalf("expected 32 hex secret, got %q", u1.Secret)
	}
	if !u1.MTProto || !u1.Web {
		t.Fatalf("expected default MTProto=true Web=true")
	}
	if !strings.HasPrefix(u1.MTProtoLink, "tg://proxy?server=87.228.113.192&port=8443&secret=ee"+u1.Secret) {
		t.Fatalf("unexpected user mtproto link: %s", u1.MTProtoLink)
	}
	if u1.WebLink != "tg://webproxy?server=tg.example.com&port=443&secret="+u1.Secret {
		t.Fatalf("unexpected user web link: %s", u1.WebLink)
	}
	if !strings.HasPrefix(u1.BridgeLink, "https://tg.example.com/?bridge=") {
		t.Fatalf("unexpected user bridge link: %s", u1.BridgeLink)
	}

	// 2. SetUser with custom flags
	err = svc.SetUser("user1", UserTelegramConfig{
		Secret:  u1.Secret,
		MTProto: false,
		Web:     true,
	})
	if err != nil {
		t.Fatalf("SetUser error: %v", err)
	}
	u1Updated, _ := svc.GetUser("user1", "87.228.113.192")
	if u1Updated.MTProto {
		t.Fatalf("expected MTProto=false after update")
	}

	// 3. NewUserSecret
	u1NewSec, err := svc.NewUserSecret("user1", "87.228.113.192")
	if err != nil {
		t.Fatalf("NewUserSecret error: %v", err)
	}
	if u1NewSec.Secret == u1.Secret {
		t.Fatalf("secret did not change after NewUserSecret")
	}

	// 4. DeleteUser
	svc.DeleteUser("user1")
	if _, err := os.Stat(svc.userCfgPath("user1")); !os.IsNotExist(err) {
		t.Fatalf("user config file still exists after DeleteUser")
	}
}
