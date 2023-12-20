/*******************************************************************************
*   (c) 2018 - 2023 ZondaX AG
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
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getDummyTx() []byte {
	dummyTx := `{
		"account_number": 1,
		"chain_id": "some_chain",
		"fee": {
			"amount": [{"amount": 10, "denom": "DEN"}],
			"gas": 5
		},
		"memo": "MEMO",
		"msgs": ["SOMETHING"],
		"sequence": 3
	}`
	dummyTx = strings.Replace(dummyTx, " ", "", -1)
	dummyTx = strings.Replace(dummyTx, "\n", "", -1)
	dummyTx = strings.Replace(dummyTx, "\t", "", -1)

	return []byte(dummyTx)
}

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserFindLedger(t *testing.T) {
	CosmosApp, err := FindLedger()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, CosmosApp)
	defer CosmosApp.Close()
}

func Test_UserGetVersion(t *testing.T) {
	CosmosApp, err := FindLedger()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer CosmosApp.Close()

	version, err := CosmosApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println("Current Cosmos app version: ", version)

	// Rework at v2.34.12 ---> Minimum required version
	assert.GreaterOrEqual(t, uint8(2), version.Major)
	if version.Major == 2 {
		assert.GreaterOrEqual(t, uint8(34), version.Minor)
		if version.Minor == 34 {
			assert.GreaterOrEqual(t, uint8(12), version.Patch)
		}
	}
}

// From v2.34.12 onwards, is possible to sign transactions using Ethereum derivation path (60)
// Verify addresses for Cosmos and Ethereum paths
// Ethereum path can be used only for a list of allowed HRP
// Check list here:
// https://github.com/cosmos/ledger-cosmos/blob/697dbd7e28cbfc8caa78d4c3bbc6febdaf6ae618/app/src/chain_config.c#L26-L30
func Test_GetAddressAndPubkey(t *testing.T) {
	CosmosApp, err := FindLedger()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer CosmosApp.Close()

	// Test with Cosmos path
	hrp := "cosmos"
	path := "m/44'/118'/0'/0/3"

	addressResponse, err := CosmosApp.GetAddressAndPubKey(path, hrp, false)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(addressResponse.pubkey),
		"Public key has wrong length: %x, expected length: %x\n", len(addressResponse.pubkey), 33)
	fmt.Printf("PUBLIC KEY: %x\n", addressResponse.pubkey)
	fmt.Printf("ADDRESS: %s\n", addressResponse.address)

	// assert.Equal(t,
	// 	"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
	// 	hex.EncodeToString(addressResponse.pubkey),
	// 	"Unexpected pubkey")

	// Test with Ethereum path --> Enable expert mode
	hrp = "inj"
	path = "m/44'/60'/0'/0/1"

	addressResponse, err = CosmosApp.GetAddressAndPubKey(path, hrp, false)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(addressResponse.pubkey),
		"Public key has wrong length: %x, expected length: %x\n", len(addressResponse.pubkey), 33)
	fmt.Printf("PUBLIC KEY: %x\n", addressResponse.pubkey)
	fmt.Printf("ADDRESS: %s\n", addressResponse.address)

	// assert.Equal(t,
	// 	"03cb5a33c61595206294140c45efa8a817533e31aa05ea18343033a0732a677005",
	// 	hex.EncodeToString(addressResponse.pubkey),
	// 	"Unexpected pubkey")

	// // Take the compressed pubkey and verify that the expected address can be computed
	// const uncompressPubKeyUint8Array = secp256k1.publicKeyConvert(resp.compressed_pk, false).subarray(1);
	// const ethereumAddressBuffer = Buffer.from(keccak(Buffer.from(uncompressPubKeyUint8Array))).subarray(-20);
	// const eth_address = bech32.encode(hrp, bech32.toWords(ethereumAddressBuffer)); // "cosmos15n2h0lzvfgc8x4fm6fdya89n78x6ee2fm7fxr3"

	// expect(resp.bech32_address).toEqual(eth_address)
	// expect(resp.bech32_address).toEqual('inj15n2h0lzvfgc8x4fm6fdya89n78x6ee2f3h7z3f')
}

func Test_UserSign(t *testing.T) {
	CosmosApp, err := FindLedger()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer CosmosApp.Close()

	hrp := "cosmos"
	path := "m/44'/118'/0'/0/0"

	message := getDummyTx()
	signatureResponse, err := CosmosApp.sign(path, hrp, SignModeAmino, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	responseAddress, err := CosmosApp.GetAddressAndPubKey(path, hrp, false)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if err != nil {
		t.Fatalf("[GetPK] Error: " + err.Error())
		return
	}

	pub2, err := btcec.ParsePubKey(responseAddress.pubkey)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := ecdsa.ParseDERSignature(signatureResponse.signatureDER)
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	hash := sha256.Sum256(message)
	verified := sig2.Verify(hash[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature: " + err.Error())
		return
	}
}

func Test_UserSignFails(t *testing.T) {
	CosmosApp, err := FindLedger()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer CosmosApp.Close()

	hrp := "cosmos"
	path := "m/44'/118'/0'/0/0"

	message := getDummyTx()
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = CosmosApp.sign(path, hrp, SignModeAmino, message)
	assert.Error(t, err)
	errMessage := err.Error()

	if errMessage != "Invalid character in JSON string" && errMessage != "Unexpected characters" {
		assert.Fail(t, "Unexpected error message returned: "+errMessage)
	}
}
