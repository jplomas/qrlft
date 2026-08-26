package main

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qcrypto "github.com/theQRL/qrlft/crypto"
	"github.com/theQRL/qrlft/sign"
	"github.com/urfave/cli/v2"
)

const testHexseed = "d2003016f53e800092ecd8d8d3cb43208c73baf505f7710d1f4cee82c601f921"

func runApp(args []string) error {
	app := newApp()
	app.ExitErrHandler = func(*cli.Context, error) {}
	return app.Run(args)
}

func TestHelpers(t *testing.T) {
	if salt, err := generateRandomSalt(16); err != nil || len(salt) != 16 {
		t.Fatalf("generateRandomSalt() = %d bytes, %v", len(salt), err)
	}
	if _, err := hexStringToRFC7468("not hex"); err == nil {
		t.Fatal("hexStringToRFC7468 expected an error")
	}
	encoded, err := hexStringToRFC7468(strings.Repeat("ab", 80))
	if err != nil || !strings.Contains(encoded, "\n") {
		t.Fatalf("hexStringToRFC7468() = %q, %v", encoded, err)
	}
	if got := split("abcdef", 2); len(got) != 3 || got[2] != "ef" {
		t.Fatalf("split() = %#v", got)
	}
	if got := split("abc", 64); len(got) != 1 || got[0] != "abc" {
		t.Fatalf("split short input = %#v", got)
	}
	for input, want := range map[string]string{"0x12": "12", "0X12": "12", "12": "12", "": ""} {
		if got := trimHexPrefix(input); got != want {
			t.Errorf("trimHexPrefix(%q) = %q, want %q", input, got, want)
		}
	}
	output("file", "hash", false)
	output("file", "hash", true)
}

func TestReadKeyFromFileFormatsAndErrors(t *testing.T) {
	tempDir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if _, _, err := readKeyFromFile(filepath.Join(tempDir, "missing")); err == nil {
		t.Fatal("expected missing-file error")
	}
	if _, _, err := readKeyFromFile(tempDir); err == nil {
		t.Fatal("expected directory error")
	}

	seedCases := []struct{ name, header, algorithm string }{
		{"dil", "DILITHIUM PRIVATE HEXSEED", qcrypto.AlgorithmDilithium},
		{"mldsa", "ML-DSA-87 PRIVATE HEXSEED", qcrypto.AlgorithmMLDSA},
	}
	for _, tc := range seedCases {
		path := write(tc.name, "-----BEGIN "+tc.header+"-----\n0x12ab\n-----END "+tc.header+"-----\n")
		seed, algorithm, err := readKeyFromFile(path)
		if err != nil || seed != "12ab" || algorithm != tc.algorithm {
			t.Errorf("readKeyFromFile(%s) = %q, %q, %v", tc.name, seed, algorithm, err)
		}
	}

	keyCases := []struct{ name, header, algorithm string }{
		{"dil-key", "DILITHIUM PRIVATE KEY", qcrypto.AlgorithmDilithium},
		{"mldsa-key", "ML-DSA-87 PRIVATE KEY", qcrypto.AlgorithmMLDSA},
	}
	for _, tc := range keyCases {
		payload := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
		path := write(tc.name, "-----BEGIN "+tc.header+"-----\n"+payload+"\n-----END "+tc.header+"-----\n")
		key, algorithm, err := readKeyFromFile(path)
		if err != nil || key != "PRIVATEKEY:010203" || algorithm != tc.algorithm {
			t.Errorf("readKeyFromFile(%s) = %q, %q, %v", tc.name, key, algorithm, err)
		}
		bad := write(tc.name+"-bad", "-----BEGIN "+tc.header+"-----\n!\n-----END "+tc.header+"-----\n")
		if _, _, err := readKeyFromFile(bad); err == nil {
			t.Errorf("expected invalid base64 error for %s", tc.name)
		}
	}

	plain, algorithm, err := readKeyFromFile(write("plain", "0X12ab\n"))
	if err != nil || plain != "12ab" || algorithm != "" {
		t.Fatalf("plain hexseed = %q, %q, %v", plain, algorithm, err)
	}
	if _, _, err := readKeyFromFile(write("invalid", "not hex")); err == nil {
		t.Fatal("expected invalid-format error")
	}
	if _, _, err := readKeyFromFile(write("bad-standard", "-----BEGIN PRIVATE KEY-----\n!\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("expected invalid standard private-key error")
	}

	signer, err := qcrypto.NewSigner(qcrypto.AlgorithmMLDSA, testHexseed, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	inner, err := asn1.Marshal(signer.GetSK())
	if err != nil {
		t.Fatal(err)
	}
	type algorithmIdentifier struct{ Algorithm asn1.ObjectIdentifier }
	type privateKeyInfo struct {
		Version    int
		Algorithm  algorithmIdentifier
		PrivateKey []byte
	}
	der, err := asn1.Marshal(privateKeyInfo{0, algorithmIdentifier{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}}, inner})
	if err != nil {
		t.Fatal(err)
	}
	expandedPath := write("expanded", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	key, algorithm, err := readKeyFromFile(expandedPath)
	if err != nil || algorithm != qcrypto.AlgorithmMLDSA || !strings.HasPrefix(key, "PRIVATEKEY:") {
		t.Fatalf("expanded standard private key = %.20q, %q, %v", key, algorithm, err)
	}
}

func TestReadPublicKeyFromFileFormatsAndErrors(t *testing.T) {
	tempDir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, _, err := readPublicKeyFromFile(filepath.Join(tempDir, "missing")); err == nil {
		t.Fatal("expected missing-file error")
	}
	if _, _, err := readPublicKeyFromFile(tempDir); err == nil {
		t.Fatal("expected directory error")
	}
	if _, _, err := readPublicKeyFromFile(write("bad-standard", "-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----\n")); err == nil {
		t.Fatal("expected invalid standard public-key error")
	}

	for _, tc := range []struct{ name, header, algorithm string }{
		{"dil", "DILITHIUM PUBLIC KEY", qcrypto.AlgorithmDilithium},
		{"mldsa", "ML-DSA-87 PUBLIC KEY", qcrypto.AlgorithmMLDSA},
	} {
		payload := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
		path := write(tc.name, "-----BEGIN "+tc.header+"-----\n"+payload+"\n-----END "+tc.header+"-----\n")
		key, algorithm, err := readPublicKeyFromFile(path)
		if err != nil || key != "010203" || algorithm != tc.algorithm {
			t.Errorf("readPublicKeyFromFile(%s) = %q, %q, %v", tc.name, key, algorithm, err)
		}
		bad := write(tc.name+"-bad", "-----BEGIN "+tc.header+"-----\n!\n-----END "+tc.header+"-----\n")
		if _, _, err := readPublicKeyFromFile(bad); err == nil {
			t.Errorf("expected invalid base64 error for %s", tc.name)
		}
	}

	long := strings.Repeat("ab", 3000)
	key, algorithm, err := readPublicKeyFromFile(write("long", long))
	if err != nil || len(key) != 5184 || algorithm != "" {
		t.Fatalf("long plain key length = %d, %q, %v", len(key), algorithm, err)
	}
	key, algorithm, err = readPublicKeyFromFile(write("short", "abcd"))
	if err != nil || key != "abcd" || algorithm != "" {
		t.Fatalf("short plain key = %q, %q, %v", key, algorithm, err)
	}
}

func TestAppCommandPaths(t *testing.T) {
	tempDir := t.TempDir()
	file := filepath.Join(tempDir, "doc.txt")
	if err := os.WriteFile(file, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}

	errorCases := [][]string{
		{"qrlft", "verify", "-a", "garbage"},
		{"qrlft", "verify", "-a", "dilithium"},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00"},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00", "--publickey=00"},
		{"qrlft", "sign", "-a", "garbage"},
		{"qrlft", "sign", "-a", "dilithium"},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=00", "--keyfile=x", file},
		{"qrlft", "sign", "-a", "mldsa", "--hexseed=00", file},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=00", "--string"},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=00"},
		{"qrlft", "publickey", "-a", "garbage"},
		{"qrlft", "publickey", "-a", "dilithium"},
		{"qrlft", "publickey", "-a", "mldsa", "--hexseed=00", "--print"},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=00"},
		{"qrlft", "hash"},
		{"qrlft", "hash", "--string"},
		{"qrlft", "hash", file},
		{"qrlft", "hash", "--sha256", filepath.Join(tempDir, "missing")},
		{"qrlft", "salt"},
		{"qrlft", "new", "-a", "garbage", "--print"},
		{"qrlft", "new", "-a", "mldsa", "--print"},
		{"qrlft", "new", "-a", "dilithium"},
	}
	for _, args := range errorCases {
		if err := runApp(args); err == nil {
			t.Errorf("newApp().Run(%q) expected error", args)
		}
	}

	for _, algorithm := range []string{"sha3-512", "sha256", "keccak-256", "keccak-512", "blake2s"} {
		if err := runApp([]string{"qrlft", "hash", "--string", "--" + algorithm, "text"}); err == nil {
			t.Errorf("string hash %s unexpectedly returned nil ExitCoder", algorithm)
		}
		if err := runApp([]string{"qrlft", "hash", "--quiet", "--" + algorithm, file}); err == nil {
			t.Errorf("file hash %s unexpectedly returned nil ExitCoder", algorithm)
		}
	}

	if err := runApp([]string{"qrlft", "salt", "8"}); err == nil {
		t.Fatal("salt success should return an ExitCoder")
	}
	if err := runApp([]string{"qrlft", "new", "-a", "dilithium", "--print"}); err == nil {
		t.Fatal("new success should return an ExitCoder")
	}

	signer, err := qcrypto.NewSigner(qcrypto.AlgorithmDilithium, testHexseed, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sign.SignFileWithAlgorithm(file, testHexseed, qcrypto.AlgorithmDilithium, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := hex.EncodeToString(signer.GetPK())
	if err := runApp([]string{"qrlft", "verify", "-a", "dilithium", "--signature=" + signature, "--publickey=" + publicKey, file}); err == nil {
		t.Fatal("verify success should return an ExitCoder")
	}
}

func TestAppDilithiumWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	keyBase := filepath.Join(tempDir, "key")
	doc := filepath.Join(tempDir, "doc.txt")
	if err := os.WriteFile(doc, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}

	commands := [][]string{
		{"qrlft", "new", "-a", "dilithium", keyBase},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=" + testHexseed, "--print"},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=" + testHexseed, filepath.Join(tempDir, "derived.pub")},
		{"qrlft", "sign", "-a", "dilithium", "--keyfile=" + keyBase, "--string", "text"},
		{"qrlft", "sign", "-a", "dilithium", "--keyfile=" + keyBase, "--quiet", doc},
		{"qrlft", "sign", "-a", "dilithium", "--keyfile=" + keyBase + ".private.hexseed", doc},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=0X" + testHexseed, "--string", "text"},
	}
	for _, args := range commands {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}

	signer, err := qcrypto.NewSigner(qcrypto.AlgorithmDilithium, testHexseed, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign.SignFileWithAlgorithm(doc, testHexseed, qcrypto.AlgorithmDilithium, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(tempDir, "signature.txt")
	if err := os.WriteFile(sigFile, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}
	pk := hex.EncodeToString(signer.GetPK())
	for _, args := range [][]string{
		{"qrlft", "verify", "-a", "dilithium", "--sigfile=" + sigFile, "--pkfile=" + keyBase + ".pub", doc},
		{"qrlft", "verify", "-a", "dilithium", "--signature=" + sig, "--publickey=" + pk, doc},
		{"qrlft", "verify", "-a", "dilithium", "--signature=" + strings.Repeat("00", 4595), "--publickey=" + pk, doc},
	} {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}

	for _, args := range [][]string{
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=" + testHexseed, tempDir},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00", "--publickey=00", tempDir},
		{"qrlft", "hash", "--sha256", tempDir},
	} {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}
}

func TestAppMLDSAWorkflow(t *testing.T) {
	tempDir := t.TempDir()
	keyBase := filepath.Join(tempDir, "mldsa")
	doc := filepath.Join(tempDir, "doc.txt")
	if err := os.WriteFile(doc, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runApp([]string{"qrlft", "new", "-a", "mldsa", "--context=test", keyBase}); err == nil {
		t.Fatal("new ML-DSA expected ExitCoder")
	}
	privateKeyFile, err := os.ReadFile(keyBase)
	if err != nil || !strings.HasPrefix(string(privateKeyFile), "-----BEGIN PRIVATE KEY-----\n") {
		t.Fatalf("standard private key = %q, %v", privateKeyFile, err)
	}
	publicKeyFile, err := os.ReadFile(keyBase + ".pub")
	if err != nil || !strings.HasPrefix(string(publicKeyFile), "-----BEGIN PUBLIC KEY-----\n") {
		t.Fatalf("standard public key = %q, %v", publicKeyFile, err)
	}
	seedFromPrivate, algorithm, err := readKeyFromFile(keyBase)
	if err != nil || algorithm != qcrypto.AlgorithmMLDSA {
		t.Fatalf("standard private key parse = %q, %q, %v", seedFromPrivate, algorithm, err)
	}
	seed, _, err := readKeyFromFile(keyBase + ".private.hexseed")
	if err != nil {
		t.Fatal(err)
	}
	if seed != seedFromPrivate {
		t.Fatal("private key and compatibility hexseed file contain different seeds")
	}
	if _, algorithm, err := readPublicKeyFromFile(keyBase + ".pub"); err != nil || algorithm != qcrypto.AlgorithmMLDSA {
		t.Fatalf("standard public key parse algorithm = %q, %v", algorithm, err)
	}

	for _, args := range [][]string{
		{"qrlft", "publickey", "-a", "mldsa", "--context=test", "--hexseed=" + seed, "--print"},
		{"qrlft", "publickey", "-a", "mldsa", "--context=test", "--hexseed=" + seed, filepath.Join(tempDir, "derived.pub")},
		{"qrlft", "sign", "-a", "mldsa", "--context=test", "--hexseed=" + seed, "--string", "text"},
		{"qrlft", "sign", "-a", "mldsa", "--context=test", "--hexseed=" + seed, "--quiet", doc},
		{"qrlft", "sign", "-a", "mldsa", "--context=test", "--keyfile=" + keyBase, doc},
	} {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}

	sig, err := sign.SignFileWithAlgorithm(doc, seed, qcrypto.AlgorithmMLDSA, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"qrlft", "verify", "-a", "mldsa", "--context=test", "--signature=" + sig, "--pkfile=" + keyBase + ".pub", doc},
		{"qrlft", "verify", "-a", "mldsa", "--context=wrong", "--signature=" + sig, "--pkfile=" + keyBase + ".pub", doc},
	} {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}
}

func TestAppValidationAndIOErrors(t *testing.T) {
	tempDir := t.TempDir()
	doc := filepath.Join(tempDir, "doc.txt")
	if err := os.WriteFile(doc, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}
	dilBase := filepath.Join(tempDir, "dil")
	mlBase := filepath.Join(tempDir, "ml")
	_ = runApp([]string{"qrlft", "new", "-a", "dilithium", dilBase})
	_ = runApp([]string{"qrlft", "new", "-a", "mldsa", "--context=test", mlBase})

	errorCases := [][]string{
		{"qrlft", "verify", "-a", "mldsa", "--signature=00", "--publickey=00", doc},
		{"qrlft", "verify", "-a", "dilithium", "--context=ignored", "--signature=00", "--publickey=00", doc},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00", "--publickey=00", filepath.Join(tempDir, "missing")},
		{"qrlft", "verify", "-a", "dilithium", "--sigfile=" + filepath.Join(tempDir, "missing"), "--publickey=00", doc},
		{"qrlft", "verify", "-a", "dilithium", "--sigfile=" + tempDir, "--publickey=00", doc},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00", "--pkfile=" + filepath.Join(tempDir, "missing"), doc},
		{"qrlft", "verify", "-a", "dilithium", "--signature=00", "--pkfile=" + mlBase + ".pub", doc},
		{"qrlft", "sign", "-a", "dilithium", "--keyfile=" + filepath.Join(tempDir, "missing"), doc},
		{"qrlft", "sign", "-a", "dilithium", "--keyfile=" + mlBase, doc},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=00", "--string", "text"},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=00", doc},
		{"qrlft", "sign", "-a", "dilithium", "--hexseed=" + testHexseed, filepath.Join(tempDir, "missing"), doc},
		{"qrlft", "sign", "-a", "dilithium", "--context=ignored", "--hexseed=" + testHexseed, "--string", "text"},
		{"qrlft", "sign", "-a", "mldsa", "--context=test", "--keyfile=" + mlBase, "--string", "text"},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=00", "--print"},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=0X" + testHexseed, "--print"},
		{"qrlft", "publickey", "-a", "dilithium", "--hexseed=" + testHexseed, tempDir},
		{"qrlft", "hash", "--sha256", filepath.Join(tempDir, "missing"), doc},
	}
	for _, args := range errorCases {
		if err := runApp(args); err == nil {
			t.Errorf("runApp(%q) expected ExitCoder", args)
		}
	}

	for _, algorithm := range []string{"dilithium", "mldsa"} {
		for _, suffix := range []string{"", ".pub", ".private.hexseed"} {
			base := filepath.Join(tempDir, algorithm+"-write-error-"+strings.ReplaceAll(suffix, ".", "-"))
			if suffix != "" {
				if err := os.Mkdir(base+suffix, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			args := []string{"qrlft", "new", "-a", algorithm}
			if algorithm == "mldsa" {
				args = append(args, "--context=test")
			}
			args = append(args, base)
			if err := runApp(args); err == nil {
				t.Errorf("expected %s key write failure for suffix %q", algorithm, suffix)
			}
		}
	}
}
