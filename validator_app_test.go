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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupValidatorApp(t *testing.T) *LedgerTendermintValidator {
	validatorApp, err := FindLedgerTendermintValidatorApp()
	require.NoError(t, err, "Failed to find Ledger Tendermint Validator App")
	t.Cleanup(func() { validatorApp.Close() })
	return validatorApp
}

func Test_ValGetVersion(t *testing.T) {
	validatorApp := setupValidatorApp(t)

	version, err := validatorApp.GetVersion()
	require.NoError(t, err, "Detected error")
	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE NOT ENABLED")
	assert.Equal(t, uint8(0x0), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x9), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x0), version.Patch, "Wrong Patch version")
}

func Test_ValGetPublicKey(t *testing.T) {
	validatorApp := setupValidatorApp(t)

	path := []uint32{44, 118, 0, 0, 0}

	for i := 1; i < 10; i++ {
		pubKey, err := validatorApp.GetPublicKeyED25519(path)
		require.NoError(t, err, "Detected error")

		assert.Equal(t, 32, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 32)
	}
}

func Test_ValSignED25519(t *testing.T) {
	t.Skip("Go support is still not available. Please refer to the Rust library")
}
