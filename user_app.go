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
	"errors"

	ledger_go "github.com/zondax/ledger-go"
)

const (
	userCLA = 0x55

	userINSGetVersion       = 0
	userINSSignSECP256K1    = 2
	userINSGetAddrSecp256k1 = 4
)

// LedgerCosmos represents a connection to the Cosmos app in a Ledger Nano S device
type LedgerCosmos struct {
	api     ledger_go.LedgerDevice
	version VersionInfo
}

// FindLedgerCosmosUserApp finds a Cosmos user app running in a ledger device
func FindLedgerCosmosUserApp() (_ *LedgerCosmos, rerr error) {
	ledgerAdmin := ledger_go.NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			ledgerAPI.Close()
		}
	}()

	app := &LedgerCosmos{ledgerAPI, VersionInfo{}}
	appVersion, err := app.GetVersion()
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] Class not supported" {
			err = errors.New("are you sure the Cosmos app is open?")
		}
		return nil, err
	}

	if err := app.CheckVersion(*appVersion); err != nil {
		return nil, err
	}

	return app, nil
}

// Close closes a connection with the Cosmos user app
func (ledger *LedgerCosmos) Close() error {
	return ledger.api.Close()
}

// CheckVersion returns true if the App version is supported by this library
func (ledger *LedgerCosmos) CheckVersion(ver VersionInfo) error {
	return CheckVersion(ver, VersionInfo{0, 2, 1, 0})
}

// GetVersion returns the current version of the Cosmos user app
func (ledger *LedgerCosmos) GetVersion() (*VersionInfo, error) {
	message := []byte{userCLA, userINSGetVersion, 0, 0, 0}
	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, errors.New("invalid response")
	}

	ledger.version = VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}

	return &ledger.version, nil
}

// SignSECP256K1 signs a transaction using Cosmos user app. It can either use
// SIGN_MODE_LEGACY_AMINO_JSON (P2=0) or SIGN_MODE_TEXTUAL (P2=1).
// this command requires user confirmation in the device
func (ledger *LedgerCosmos) SignSECP256K1(bip32Path []uint32, transaction []byte, p2 byte) ([]byte, error) {
	if p2 > 1 {
		return nil, errors.New("only values of SIGN_MODE_LEGACY_AMINO (P2=0) and SIGN_MODE_TEXTUAL (P2=1) are allowed")
	}

	// Get path bytes
	pathBytes, err := GetBip32bytes(bip32Path, 3)
	if err != nil {
		return nil, err
	}

	// Prepare chunks using ledger-go chunking
	chunks := ledger_go.PrepareChunks(pathBytes, transaction)

	// Use ProcessChunks with custom error handler
	return ledger_go.ProcessChunks(ledger.api, chunks, userCLA, userINSSignSECP256K1, p2, cosmosErrorHandler)
}

// GetPublicKeySECP256K1 retrieves the public key for the corresponding bip32 derivation path (compressed)
// this command DOES NOT require user confirmation in the device
func (ledger *LedgerCosmos) GetPublicKeySECP256K1(bip32Path []uint32) ([]byte, error) {
	pubkey, _, err := ledger.getAddressPubKeySECP256K1(bip32Path, "cosmos", false)
	return pubkey, err
}

func validHRPByte(b byte) bool {
	// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
	return b >= 33 && b <= 126
}

// GetAddressPubKeySECP256K1 returns the pubkey (compressed) and address (bech(
// this command requires user confirmation in the device
func (ledger *LedgerCosmos) GetAddressPubKeySECP256K1(bip32Path []uint32, hrp string) (pubkey []byte, addr string, err error) {
	return ledger.getAddressPubKeySECP256K1(bip32Path, hrp, true)
}


// cosmosErrorHandler provides custom error handling for Cosmos app
func cosmosErrorHandler(err error, response []byte, instruction byte) error {
	if err.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
		// In this special case, we can extract additional info
		errorMsg := string(response)
		switch errorMsg {
		case "ERROR: JSMN_ERROR_NOMEM":
			return errors.New("Not enough tokens were provided")
		case "PARSER ERROR: JSMN_ERROR_INVAL":
			return errors.New("Unexpected character in JSON string")
		case "PARSER ERROR: JSMN_ERROR_PART":
			return errors.New("The JSON string is not a complete.")
		}
		if errorMsg != "" {
			return errors.New(errorMsg)
		}
		return err
	}
	if err.Error() == "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)" {
		errorMsg := string(response)
		if errorMsg != "" {
			return errors.New(errorMsg)
		}
		return err
	}
	return err
}

// getAddressPubKeySECP256K1 returns the pubkey (compressed) and address (bech32)
// this command requires user confirmation in the device
func (ledger *LedgerCosmos) getAddressPubKeySECP256K1(bip32Path []uint32, hrp string, requireConfirmation bool) (pubkey []byte, addr string, err error) {
	if len(hrp) > 83 {
		return nil, "", errors.New("hrp len should be <10")
	}

	hrpBytes := []byte(hrp)
	for _, b := range hrpBytes {
		if !validHRPByte(b) {
			return nil, "", errors.New("all characters in the HRP must be in the [33, 126] range")
		}
	}

	pathBytes, err := GetBip32bytes(bip32Path, 3)
	if err != nil {
		return nil, "", err
	}

	p1 := byte(0)
	if requireConfirmation {
		p1 = byte(1)
	}

	// Prepare message
	header := []byte{userCLA, userINSGetAddrSecp256k1, p1, 0, 0}
	message := append(header, byte(len(hrpBytes)))
	message = append(message, hrpBytes...)
	message = append(message, pathBytes...)
	message[4] = byte(len(message) - len(header)) // update length

	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, "", err
	}
	if len(response) < 35+len(hrp) {
		return nil, "", errors.New("Invalid response")
	}

	pubkey = response[0:33]
	addr = string(response[33:])

	return pubkey, addr, err
}
