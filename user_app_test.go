/*******************************************************************************
*   (c) Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package ledger_cosmos_go

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

const (
	testPubKeyLength = 33

	// Expected version for the Cosmos app (update when testing with different versions)
	expectedMajorVersion = 0x2
	expectedMinorVersion = 0x26
	expectedPatchVersion = 0x4
)

// Test paths
var (
	standardPath = []uint32{44, 118, 0, 0, 0}
	customPath   = []uint32{44, 118, 5, 0, 21}
	signTestPath = []uint32{44, 118, 0, 0, 5}
)

// Expected public keys for the test mnemonic at different derivation paths
var expectedPubKeys = []string{
	"034fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe87",
	"0260d0487a3dfce9228eee2d0d83a40f6131f551526c8e52066fe7fe1e4a509666",
	"03a2670393d02b162d0ed06a08041e80d86be36c0564335254df7462447eb69ab3",
	"033222fc61795077791665544a90740e8ead638a391a3b8f9261f4a226b396c042",
	"03f577473348d7b01e7af2f245e36b98d181bc935ec8b552cde5932b646dc7be04",
	"0222b1a5486be0a2d5f3c5866be46e05d1bde8cda5ea1c4c77a9bc48d2fa2753bc",
	"0377a1c826d3a03ca4ee94fc4dea6bccb2bac5f2ac0419a128c29f8e88f1ff295a",
	"031b75c84453935ab76f8c8d0b6566c3fcc101cc5c59d7000bfc9101961e9308d9",
	"038905a42433b1d677cc8afd36861430b9a8529171b0616f733659f131c3f80221",
	"038be7f348902d8c20bc88d32294f4f3b819284548122229decd1adf1a7eb0848b",
}

func connectToLedger(t *testing.T) *LedgerCosmos {
	t.Helper()
	userApp, err := FindLedgerCosmosUserApp()
	require.NoError(t, err, "Failed to connect to Ledger device")
	return userApp
}

func TestFindLedgerCosmosUserApp(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	assert.NotNil(t, userApp)
}

func TestGetVersion(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	version, err := userApp.GetVersion()
	require.NoError(t, err)

	t.Logf("App version: %s", version)

	assert.Equal(t, uint8(0x0), version.AppMode, "Testing mode should be disabled")
	assert.Equal(t, uint8(expectedMajorVersion), version.Major, "Unexpected major version")
	assert.Equal(t, uint8(expectedMinorVersion), version.Minor, "Unexpected minor version")
	assert.Equal(t, uint8(expectedPatchVersion), version.Patch, "Unexpected patch version")
}

func TestGetPublicKeySECP256K1(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	pubKey, err := userApp.GetPublicKeySECP256K1(customPath)
	require.NoError(t, err)

	t.Logf("Public key: %x", pubKey)

	assert.Len(t, pubKey, testPubKeyLength, "Public key has wrong length")
	assert.Equal(t,
		"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
		hex.EncodeToString(pubKey),
	)
}

func TestGetAddressPubKeySECP256K1_StandardPath(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(standardPath, "cosmos")
	require.NoError(t, err)

	t.Logf("Public key: %x", pubKey)
	t.Logf("Address: %s", addr)

	assert.Len(t, pubKey, testPubKeyLength, "Public key has wrong length")
	assert.Equal(t,
		"034fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe87",
		hex.EncodeToString(pubKey),
	)
	assert.Equal(t, "cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h", addr)
}

func TestGetAddressPubKeySECP256K1_CustomPath(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(customPath, "cosmos")
	require.NoError(t, err)

	t.Logf("Public key: %x", pubKey)
	t.Logf("Address: %s", addr)

	assert.Len(t, pubKey, testPubKeyLength, "Public key has wrong length")
	assert.Equal(t,
		"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
		hex.EncodeToString(pubKey),
	)
	assert.Equal(t, "cosmos162zm3k8mc685592d7vej2lxrp58mgmkcec76d6", addr)
}

func TestGetPublicKeySECP256K1_HDPaths(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	path := []uint32{44, 118, 0, 0, 0}

	for i := uint32(0); i < uint32(len(expectedPubKeys)); i++ {
		path[4] = i

		pubKey, err := userApp.GetPublicKeySECP256K1(path)
		require.NoError(t, err, "Failed to get public key for index %d", i)

		assert.Len(t, pubKey, testPubKeyLength, "Public key has wrong length for index %d", i)
		assert.Equal(t, expectedPubKeys[i], hex.EncodeToString(pubKey),
			"Public key for path 44'/118'/0'/0'/%d does not match", i)

		// Verify the public key is valid by parsing it
		_, err = btcec.ParsePubKey(pubKey)
		require.NoError(t, err, "Failed to parse public key for index %d", i)
	}
}

func TestSignSECP256K1(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	message := getTestTransaction()

	signature, err := userApp.SignSECP256K1(signTestPath, message, SignModeLegacyAminoJSON)
	require.NoError(t, err, "Failed to sign transaction")

	// Get the public key for verification
	pubKey, err := userApp.GetPublicKeySECP256K1(signTestPath)
	require.NoError(t, err, "Failed to get public key")

	// Parse the public key
	parsedPubKey, err := btcec.ParsePubKey(pubKey)
	require.NoError(t, err, "Failed to parse public key")

	// Parse the DER signature
	parsedSig, err := ecdsa.ParseDERSignature(signature)
	require.NoError(t, err, "Failed to parse DER signature")

	// Verify the signature
	hash := sha256.Sum256(message)
	verified := parsedSig.Verify(hash[:], parsedPubKey)
	assert.True(t, verified, "Signature verification failed")
}

func TestSignSECP256K1_InvalidTransaction(t *testing.T) {
	userApp := connectToLedger(t)
	defer userApp.Close()

	// Prepend garbage to create invalid JSON
	message := append([]byte{65}, getTestTransaction()...)

	_, err := userApp.SignSECP256K1(signTestPath, message, SignModeLegacyAminoJSON)
	require.Error(t, err)

	// Check for expected error messages
	errMsg := err.Error()
	validErrors := []string{
		"Invalid character in JSON string",
		"Unexpected characters",
		"unexpected character in JSON string",
	}

	isValidError := false
	for _, validErr := range validErrors {
		if errMsg == validErr {
			isValidError = true
			break
		}
	}
	assert.True(t, isValidError, "Unexpected error message: %s", errMsg)
}

// getTestTransaction returns a valid Cosmos transaction for testing.
// Transaction format from ledger-cosmos tests_zemu/tests/common.ts (example_tx_str_basic)
func getTestTransaction() []byte {
	tx := `{"account_number":"108","chain_id":"cosmoshub-4","fee":{"amount":[{"amount":"600","denom":"uatom"}],"gas":"200000"},"memo":"","msgs":[{"type":"cosmos-sdk/MsgWithdrawDelegationReward","value":{"delegator_address":"cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h","validator_address":"cosmosvaloper1kn3wugetjuy4zetlq6wadchfhvu3x740ae6z6x"}},{"type":"cosmos-sdk/MsgWithdrawDelegationReward","value":{"delegator_address":"cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h","validator_address":"cosmosvaloper1sjllsnramtg3ewxqwwrwjxfgc4n4ef9u2lcnj0"}}],"sequence":"106"}`
	return []byte(tx)
}
