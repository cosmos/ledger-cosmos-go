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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/tendermint/crypto"
)

func Test_UserGetVersion(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		assert.Error(t, err)
	}

	userApp.api.Logging = true

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x1), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x0), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x0), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		assert.Error(t, err)
	}

	userApp.api.Logging = true

	path := []uint32{44, 118, 0, 0, 0}

	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		assert.FailNow(t, "Detected error, err: %s\n", err.Error())
	}

	assert.Equal(
		t,
		65,
		len(pubKey),
		"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	_, err = secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	require.Nil(t, err, "Error parsing public key err: %s\n", err)
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

	path := []uint32{44, 118, 0, 0, 0}

	message := getDummyTx()
	signature, err := userApp.SignSECP256K1(path, message)
	if err != nil {
		assert.FailNow(t,"[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		assert.FailNow(t, "Detected error, err: %s\n", err.Error())
	}

	if err != nil {
		assert.FailNow(t, "[GetPK] Error: " + err.Error())
		return
	}

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	if err != nil {
		assert.FailNow(t, "[ParsePK] Error: " + err.Error())
		return
	}

	sig__, err := secp256k1.ParseDERSignature(signature[:], secp256k1.S256())
	if err != nil {
		assert.FailNow(t, "[ParseSig] Error: " + err.Error())
		return
	}

	verified := sig__.Verify(crypto.Sha256(message), pub__)
	if !verified {
		assert.FailNow(t, "[VerifySig] Error verifying signature: " + err.Error())
		return
	}
}
