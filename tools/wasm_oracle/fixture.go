package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

const (
	pinnedVersion   = "1.1.34"
	pinnedWASMSize  = 297238
	pinnedWASMHash  = "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"
	upgradeVersion  = "1.1.74"
	upgradeWASMSize = 298606
	upgradeWASMHash = "6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d"
	maxFixtureSize  = 2 << 20
)

var (
	fixtureNames         = []string{"credential.json", "runtime-fields.json", "model-cache.json", "infer-user.json", "infer-user-no-org.json"}
	fixtureJSONNames     = []string{"credential.json", "infer-user-no-org.json", "infer-user.json", "manifest.json", "model-cache.json", "runtime-fields.json"}
	pinnedDocumentHashes = map[string]string{
		"credential.json":        "07b80f1d48141d763dab7065465b0bd531ae8e490f56a1999322b2faa1d29574",
		"infer-user-no-org.json": "1f7d66201ff1b3d25890cd4399d2aca67b582d938d715f2f0fb048a62e0e78d6",
		"infer-user.json":        "9732d0ca933bcf53e2e26e09b0e6a8ec46bd310ce925a8c2b74f24ab6f9b99ed",
		"model-cache.json":       "7c9dd168e83f6461b1826aae6b475c6ed419f5b9f45b4bfbecfbfd9617407cc8",
		"runtime-fields.json":    "9ab327de55b7ece6d429783152b77298c3b0eb1a51776213741ba8784954aaf0",
	}
)

type oracleError struct{ category string }

func (e *oracleError) Error() string { return e.category }
func fail(category string) error     { return &oracleError{category: category} }
func categoryOf(err error) string {
	var target *oracleError
	if errors.As(err, &target) {
		return target.category
	}
	if err == nil {
		return ""
	}
	return "internal"
}

type oracleIdentity struct {
	Version string `json:"version"`
	Size    int    `json:"size"`
	SHA256  string `json:"sha256"`
}
type fixtureManifest struct {
	Version   string            `json:"version"`
	Size      int               `json:"size"`
	SHA256    string            `json:"sha256"`
	Documents map[string]string `json:"documents"`
}
type fixtureDocument struct {
	Oracle     oracleIdentity  `json:"oracle"`
	Input      json.RawMessage `json:"input"`
	Transcript transcript      `json:"transcript"`
	Expected   json.RawMessage `json:"expected"`
}
type fixturePolicy struct {
	Identity       oracleIdentity
	DocumentHashes map[string]string
}

type entropyRead struct {
	Length int    `json:"length"`
	Bytes  []byte `json:"-"`
}

func (r *entropyRead) UnmarshalJSON(data []byte) error {
	var wire struct {
		Length int    `json:"length"`
		Bytes  string `json:"bytes"`
	}
	if err := decodeStrictObject(data, &wire, []string{"length", "bytes"}); err != nil || wire.Length < 0 {
		return fail("fixture-schema")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(wire.Bytes)
	if err != nil || len(decoded) != wire.Length || base64.StdEncoding.EncodeToString(decoded) != wire.Bytes {
		return fail("fixture-schema")
	}
	r.Length, r.Bytes = wire.Length, decoded
	return nil
}
func (r entropyRead) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Length int    `json:"length"`
		Bytes  string `json:"bytes"`
	}{r.Length, base64.StdEncoding.EncodeToString(r.Bytes)})
}

type transcript struct {
	UnixMilli    []int64       `json:"unix_milli"`
	EntropyReads []entropyRead `json:"entropy_reads"`
}

type fixtureSet map[string]fixtureDocument

func validateFixtureSafety(_ string, data []byte) error {
	for _, marker := range []string{
		"/home/", "/Users/", "/root/", `\\Users\\`, `C:\\Users\\`, ".qoder", "re/secrets", "SENTINEL-PROTOCOL-SECRET",
		"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "AKIA", "github_pat_", "ghp_", "xoxb-",
	} {
		if bytes.Contains(data, []byte(marker)) {
			return fail("fixture-safety")
		}
	}
	return nil
}

func fixtureNamesForVersion(version string) []string {
	names := append([]string(nil), fixtureNames...)
	if version == upgradeVersion {
		names = append(names, "compatibility.json")
	}
	return names
}

func validateInventory(dir string) error { return validateVersionInventory(dir, pinnedVersion) }

func validateVersionInventory(dir, version string) error {
	expected := append(fixtureNamesForVersion(version), "manifest.json")
	sort.Strings(expected)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fail("fixture-inventory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(expected) {
		return fail("fixture-inventory")
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		child, statErr := os.Lstat(path)
		if statErr != nil || !child.Mode().IsRegular() || child.Mode()&os.ModeSymlink != 0 {
			return fail("fixture-inventory")
		}
		got = append(got, entry.Name())
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, expected) {
		return fail("fixture-inventory")
	}
	return nil
}

func decodeCanonicalJSON(data []byte, destination any) error {
	if len(data) == 0 || data[len(data)-1] != '\n' || bytes.Contains(data, []byte{'\r'}) || bytes.HasSuffix(data, []byte("\n\n")) {
		return fail("fixture-canonical-json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fail("fixture-canonical-json")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fail("fixture-canonical-json")
	}
	canonical, err := json.MarshalIndent(destination, "", "  ")
	if err != nil {
		return fail("fixture-canonical-json")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return fail("fixture-canonical-json")
	}
	return nil
}

func decodeStrictObject(data []byte, destination any, keys []string) error {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&object); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || len(object) != len(keys) {
		return fail("fixture-schema")
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fail("fixture-schema")
		}
	}
	return json.Unmarshal(data, destination)
}

func validateFixtureSet(dir string, policy fixturePolicy) (fixtureSet, error) {
	manifestData, err := readBoundedRegularFile(filepath.Join(dir, "manifest.json"), maxFixtureSize, "fixture-read")
	if err != nil {
		return nil, err
	}
	if err := validateFixtureSafety("manifest.json", manifestData); err != nil {
		return nil, err
	}
	var manifest fixtureManifest
	if err := decodeCanonicalJSON(manifestData, &manifest); err != nil {
		return nil, err
	}
	if manifest.Version != policy.Identity.Version || manifest.Size != policy.Identity.Size || manifest.SHA256 != policy.Identity.SHA256 {
		return nil, fail("fixture-oracle-identity")
	}
	if !reflect.DeepEqual(manifest.Documents, policy.DocumentHashes) {
		return nil, fail("fixture-manifest-hash")
	}
	if err := validateVersionInventory(dir, policy.Identity.Version); err != nil {
		return nil, err
	}
	names := fixtureNamesForVersion(policy.Identity.Version)
	fixtures := make(fixtureSet, len(names))
	for _, name := range names {
		data, err := readBoundedRegularFile(filepath.Join(dir, name), maxFixtureSize, "fixture-read")
		if err != nil {
			return nil, err
		}
		if err := validateFixtureSafety(name, data); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != policy.DocumentHashes[name] {
			return nil, fail("fixture-document-hash")
		}
		var fixture fixtureDocument
		if err := decodeCanonicalJSON(data, &fixture); err != nil {
			return nil, err
		}
		if fixture.Oracle != policy.Identity {
			return nil, fail("fixture-oracle-identity")
		}
		if err := validateFixtureSchema(name, fixture); err != nil {
			return nil, err
		}
		fixtures[name] = fixture
	}
	if err := validateCrossFixtureRelationships(fixtures); err != nil {
		return nil, err
	}
	return fixtures, nil
}

// The historical pin is intentionally independent of the production version.
// Local 1.1.12 bytes match this historical 1.1.34 identity; this is not evidence
// that the local CLI itself was version 1.1.34.
func pinnedPolicy() fixturePolicy {
	return fixturePolicy{Identity: oracleIdentity{pinnedVersion, pinnedWASMSize, pinnedWASMHash}, DocumentHashes: pinnedDocumentHashes}
}

func policyForVersion(version string) (fixturePolicy, error) {
	switch version {
	case pinnedVersion:
		return pinnedPolicy(), nil
	case upgradeVersion:
		return fixturePolicy{Identity: oracleIdentity{upgradeVersion, upgradeWASMSize, upgradeWASMHash}, DocumentHashes: upgradeDocumentHashes}, nil
	default:
		return fixturePolicy{}, fail("fixture-oracle-identity")
	}
}

var upgradeDocumentHashes = map[string]string{
	"compatibility.json":     "867fc46e79433a4b5c0c18eda59118203a064884408b31c0d2f1cb28940ef320",
	"credential.json":        "f976e8464cc3984269fa986538892e231ce0763c757a3ca2175b995a8ecce6e2",
	"infer-user-no-org.json": "65447bc0e8ec7be7f5687b04b7bbfe08d98b2aea1ec8e5dffe8171a897dfd668",
	"infer-user.json":        "a9e7341e45cc32a81ef814bd79bb8c833972796f7fe34d55e90cf36aeb11f549",
	"model-cache.json":       "0344ac2f3680cd29ea3fddd69d57ca5923ab0e3cf62891e29a16970a295e03a0",
	"runtime-fields.json":    "bbc45fab848a4aee116ed0670d51b0e14e66494c1ef4d8df9e0e2da6239eb734",
}

func policyForIdentity(identity oracleIdentity) (fixturePolicy, error) {
	policy, err := policyForVersion(identity.Version)
	if err != nil || policy.Identity != identity {
		return fixturePolicy{}, fail("fixture-oracle-identity")
	}
	return policy, nil
}

func policyForDirectory(dir string) (fixturePolicy, error) {
	data, err := readBoundedRegularFile(filepath.Join(dir, "manifest.json"), maxFixtureSize, "fixture-read")
	if err != nil {
		return fixturePolicy{}, err
	}
	if err := validateFixtureSafety("manifest.json", data); err != nil {
		return fixturePolicy{}, err
	}
	var manifest fixtureManifest
	if err := decodeCanonicalJSON(data, &manifest); err != nil {
		return fixturePolicy{}, err
	}
	return policyForIdentity(oracleIdentity{manifest.Version, manifest.Size, manifest.SHA256})
}

func validateFixtureSchema(name string, fixture fixtureDocument) error {
	return validateNestedFixture(name, fixture)
}

func mustDecode[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return value, fail("fixture-schema")
	}
	return value, nil
}
func compactJSON(raw json.RawMessage) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fail("fixture-schema")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", fail("fixture-schema")
	}
	return string(data), nil
}
func validateWASM(data []byte) error {
	for _, version := range []string{pinnedVersion, upgradeVersion} {
		policy, _ := policyForVersion(version)
		if len(data) == policy.Identity.Size {
			return validateWASMForIdentity(data, policy.Identity)
		}
	}
	return fail("wasm-identity-size")
}

func validateWASMForIdentity(data []byte, identity oracleIdentity) error {
	if _, err := policyForIdentity(identity); err != nil {
		return err
	}
	if len(data) != identity.Size {
		return fail("wasm-identity-size")
	}
	sum := sha256.Sum256(data)
	if fmt.Sprintf("%x", sum) != identity.SHA256 {
		return fail("wasm-identity-sha256")
	}
	return nil
}
