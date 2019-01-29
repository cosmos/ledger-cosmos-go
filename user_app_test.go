// +build ledger_device

/*******************************************************************************
*   (c) 2018 ZondaX GmbH
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
	"encoding/hex"
	"fmt"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"strings"
	"testing"
)

func Test_UserFindLedger(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, userApp)
}

func Test_UserGetVersion(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	userApp.api.Logging = true

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x1), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x0), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x1), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	userApp.api.Logging = true

	path := []uint32{44, 118, 0, 0, 0}

	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(
		t,
		65,
		len(pubKey),
		"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	fmt.Printf("PUBLIC KEY: %x\n", pubKey)

	_, err = secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	require.Nil(t, err, "Error parsing public key err: %s\n", err)
}

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserPK_HDPaths(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	userApp.api.Logging = true

	path := []uint32{44, 118, 0, 0, 0}

	expected := []string{
		"044fef9cd7c4c63588d3b03feb5281b9d232cba34d6f3d71aee59211ffbfe1fe877bff8521bf5243e80be922e51cee0faa8346b113fdec822c4d902e42b22bc345",
		"0460d0487a3dfce9228eee2d0d83a40f6131f551526c8e52066fe7fe1e4a509666d60da24e97777510db9b238870e184891b580610ec6dafaf12c7abffed3670c6",
		"04a2670393d02b162d0ed06a08041e80d86be36c0564335254df7462447eb69ab3f5a54ab07a8622ab23c28e9240ce58f4015ec401d95b08221b74e2a4a209ba6d",
		"043222fc61795077791665544a90740e8ead638a391a3b8f9261f4a226b396c042a118bb64eccd89941d73de7cb12beed5a47de61049c7fc0d4708a4a0f5637957",
		"04f577473348d7b01e7af2f245e36b98d181bc935ec8b552cde5932b646dc7be0415b9fd94af37dc295e25e35d3840fdd3cb1d0baa411bdc00d15dca427abdff3f",
		"0422b1a5486be0a2d5f3c5866be46e05d1bde8cda5ea1c4c77a9bc48d2fa2753bcbb49b6c9d4be25bed7fb75c2e0c43c25175e88893c4f7963398a5aac3230c79e",
		"0477a1c826d3a03ca4ee94fc4dea6bccb2bac5f2ac0419a128c29f8e88f1ff295ac6a16c770d38ee0e55bec83e8d8e3f1b1616ce77055a928255919340053a477d",
		"041b75c84453935ab76f8c8d0b6566c3fcc101cc5c59d7000bfc9101961e9308d9228b0af378c4e6a38eeaf18175d2b2a7ab3fad9c9a4b117775f2e4a4ac633aff",
		"048905a42433b1d677cc8afd36861430b9a8529171b0616f733659f131c3f80221e222d162dbcde7c77be3d82b4f666c2acc1e25aaeb3e4fadfb8c7c6b1282374b",
		"048be7f348902d8c20bc88d32294f4f3b819284548122229decd1adf1a7eb0848bc4fbd7ac5bae3a854f2bcb0831c4550f48752f630a33a088d0fd166d8d3435d9",
	}

	for i := uint32(0); i < 10; i++ {
		path[4] = i

		pubKey, err := userApp.GetPublicKeySECP256K1(path)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			65,
			len(pubKey),
			"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(pubKey),
			"Public key 44'/118'/0'/0/%d does not match\n", i)

		_, err = secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
		require.Nil(t, err, "Error parsing public key err: %s\n", err)

	}
}

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

func Test_UserSign(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		assert.Error(t, err)
	}

	userApp.api.Logging = true

	path := []uint32{44, 118, 0, 0, 5}

	message := getDummyTx()
	signature, err := userApp.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if err != nil {
		t.Fatalf("[GetPK] Error: " + err.Error())
		return
	}

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig__, err := secp256k1.ParseDERSignature(signature[:], secp256k1.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	verified := sig__.Verify(crypto.Sha256(message), pub__)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature: " + err.Error())
		return
	}
}
