package tgproxy

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/sha256"
 "encoding/hex"
 "testing"
)

// Independent MTProxy obfuscated2 handshake: AES-CTR advances across all 64
// header bytes; only the encrypted tail replaces the original header on wire.
func TestAuditStandardObfuscated2Header(t *testing.T) {
 const secretHex = "0123456789abcdef0123456789abcdef"
 secret, _ := hex.DecodeString(secretHex)
 var plain [64]byte
 for i := 0; i < 56; i++ { plain[i] = byte(i + 1) }
 copy(plain[56:60], []byte{0xee, 0xee, 0xee, 0xee})
 plain[60] = 2
 material := append(append([]byte(nil), plain[8:40]...), secret...)
 key := sha256.Sum256(material)
 block, _ := aes.NewCipher(key[:])
 stream := cipher.NewCTR(block, plain[40:56])
 var encrypted [64]byte
 stream.XORKeyStream(encrypted[:], plain[:])
 wire := plain
 copy(wire[56:], encrypted[56:])
 sec, err := parseMtgSecret(secretHex, "example.com")
 if err != nil { t.Fatal(err) }
 parsed := parseObfuscated2Frame(wire[:], []mtgParsedSecret{{Name:"alice", Secret:sec}})
 if !parsed.matched || parsed.dc != 2 { t.Fatalf("valid standard header rejected: matched=%v dc=%d", parsed.matched, parsed.dc) }
}
