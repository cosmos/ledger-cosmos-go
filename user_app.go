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
	"fmt"
	"strings"

	ledger_go "github.com/zondax/ledger-go"
)

const (
	userCLA = 0x55

	userINSGetVersion       = 0
	userINSSignSECP256K1    = 2
	userINSGetAddrSecp256k1 = 4

	// hardenCount is the number of path elements that should be hardened
	hardenCount = 3

	// pubKeyLength is the length of a compressed SECP256K1 public key
	pubKeyLength = 33

	// maxHRPLength is the maximum length of the human-readable part in bech32 addresses
	maxHRPLength = 83

	// minHRPByte is the minimum valid byte value for HRP characters
	minHRPByte = 33

	// maxHRPByte is the maximum valid byte value for HRP characters
	maxHRPByte = 126
)

// Sign mode constants for SignSECP256K1
const (
	SignModeLegacyAminoJSON byte = 0
	SignModeTextual         byte = 1
)

// Error variables for common error conditions
var (
	ErrInvalidResponse     = errors.New("invalid response")
	ErrInvalidSignMode     = errors.New("invalid sign mode: only SIGN_MODE_LEGACY_AMINO (0) and SIGN_MODE_TEXTUAL (1) are allowed")
	ErrHRPTooLong          = errors.New("HRP length exceeds maximum allowed (83 characters)")
	ErrInvalidHRPCharacter = errors.New("all characters in the HRP must be in the [33, 126] range")
	ErrCosmosAppNotOpen    = errors.New("are you sure the Cosmos app is open?")
)

// MinRequiredVersion is the minimum version of the Cosmos app required by this library
var MinRequiredVersion = VersionInfo{Major: 2, Minor: 1, Patch: 0}

// LedgerCosmos represents a connection to the Cosmos app in a Ledger device
type LedgerCosmos struct {
	api     ledger_go.LedgerDevice
	version VersionInfo
}

// FindLedgerCosmosUserApp finds and connects to a Cosmos user app running in a Ledger device.
// It returns an error if no device is found, the app is not open, or the version is not supported.
func FindLedgerCosmosUserApp() (*LedgerCosmos, error) {
	ledgerAdmin := ledger_go.NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, err
	}

	app := &LedgerCosmos{api: ledgerAPI}

	appVersion, err := app.GetVersion()
	if err != nil {
		ledgerAPI.Close()
		// Check if the error indicates the Cosmos app is not open
		// Using string contains for robustness against minor message variations
		if strings.Contains(err.Error(), "CLA_NOT_SUPPORTED") {
			return nil, ErrCosmosAppNotOpen
		}
		return nil, err
	}

	if err := app.CheckVersion(*appVersion); err != nil {
		ledgerAPI.Close()
		return nil, err
	}

	return app, nil
}

// Close closes the connection with the Ledger device.
func (ledger *LedgerCosmos) Close() error {
	return ledger.api.Close()
}

// CheckVersion verifies that the app version meets the minimum required version.
func (ledger *LedgerCosmos) CheckVersion(ver VersionInfo) error {
	return CheckVersion(ver, MinRequiredVersion)
}

// GetVersion returns the current version of the Cosmos app.
func (ledger *LedgerCosmos) GetVersion() (*VersionInfo, error) {
	message := []byte{userCLA, userINSGetVersion, 0, 0, 0}
	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, ErrInvalidResponse
	}

	ledger.version = VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}

	return &ledger.version, nil
}

// SignSECP256K1 signs a transaction using the Cosmos app.
// The signMode parameter determines the signing mode:
//   - SignModeLegacyAminoJSON (0): SIGN_MODE_LEGACY_AMINO_JSON
//   - SignModeTextual (1): SIGN_MODE_TEXTUAL
//
// This command requires user confirmation on the device.
func (ledger *LedgerCosmos) SignSECP256K1(bip32Path []uint32, transaction []byte, signMode byte) ([]byte, error) {
	if signMode > SignModeTextual {
		return nil, ErrInvalidSignMode
	}

	pathBytes, err := GetBip32bytes(bip32Path, hardenCount)
	if err != nil {
		return nil, err
	}

	chunks := ledger_go.PrepareChunks(pathBytes, transaction)

	return ledger_go.ProcessChunks(ledger.api, chunks, userCLA, userINSSignSECP256K1, signMode, cosmosErrorHandler)
}

// GetPublicKeySECP256K1 retrieves the compressed public key for the given BIP32 derivation path.
// This command does NOT require user confirmation on the device.
func (ledger *LedgerCosmos) GetPublicKeySECP256K1(bip32Path []uint32) ([]byte, error) {
	pubkey, _, err := ledger.getAddressPubKeySECP256K1(bip32Path, "cosmos", false)
	return pubkey, err
}

// GetAddressPubKeySECP256K1 returns the compressed public key and bech32 address
// for the given BIP32 derivation path and human-readable prefix (HRP).
// This command requires user confirmation on the device.
func (ledger *LedgerCosmos) GetAddressPubKeySECP256K1(bip32Path []uint32, hrp string) ([]byte, string, error) {
	return ledger.getAddressPubKeySECP256K1(bip32Path, hrp, true)
}

// getAddressPubKeySECP256K1 is the internal implementation for retrieving public key and address.
func (ledger *LedgerCosmos) getAddressPubKeySECP256K1(bip32Path []uint32, hrp string, requireConfirmation bool) ([]byte, string, error) {
	if len(hrp) > maxHRPLength {
		return nil, "", ErrHRPTooLong
	}

	if err := validateHRP(hrp); err != nil {
		return nil, "", err
	}

	pathBytes, err := GetBip32bytes(bip32Path, hardenCount)
	if err != nil {
		return nil, "", err
	}

	message := buildAddressMessage(hrp, pathBytes, requireConfirmation)

	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, "", err
	}

	// Minimum response: pubkey (33) + hrp + "1" separator + data (min 1) + checksum (6)
	// Example: cosmos1... = "cosmos" (6) + "1" (1) + address_data + checksum (6)
	minResponseLength := pubKeyLength + len(hrp) + 1 + 1 + 6
	if len(response) < minResponseLength {
		return nil, "", ErrInvalidResponse
	}

	pubkey := response[:pubKeyLength]
	addr := string(response[pubKeyLength:])

	return pubkey, addr, nil
}

// validateHRP checks if all characters in the HRP are valid according to BIP-173.
// Valid characters are in the ASCII range [33, 126] and must be lowercase (no uppercase A-Z).
// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
func validateHRP(hrp string) error {
	for _, b := range []byte(hrp) {
		if b < minHRPByte || b > maxHRPByte {
			return ErrInvalidHRPCharacter
		}
		// BIP-173 requires lowercase: reject uppercase letters (A-Z = 65-90)
		if b >= 'A' && b <= 'Z' {
			return ErrInvalidHRPCharacter
		}
	}
	return nil
}

// buildAddressMessage constructs the APDU message for getting address and public key.
func buildAddressMessage(hrp string, pathBytes []byte, requireConfirmation bool) []byte {
	hrpBytes := []byte(hrp)

	p1 := byte(0)
	if requireConfirmation {
		p1 = 1
	}

	// Build payload: hrp length + hrp + pathBytes
	payload := append([]byte{byte(len(hrpBytes))}, hrpBytes...)
	payload = append(payload, pathBytes...)

	// Build APDU header and append payload
	message := []byte{userCLA, userINSGetAddrSecp256k1, p1, 0, byte(len(payload))}
	return append(message, payload...)
}

// cosmosErrorHandler provides custom error handling for Cosmos app APDU errors.
func cosmosErrorHandler(err error, response []byte, _ byte) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()
	responseMsg := string(response)

	switch errMsg {
	case "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect":
		return handleBadKeyError(responseMsg, err)
	case "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)":
		if responseMsg != "" {
			return errors.New(responseMsg)
		}
	}

	return err
}

// handleBadKeyError handles the BAD_KEY_HANDLE error with specific error messages.
func handleBadKeyError(responseMsg string, originalErr error) error {
	switch responseMsg {
	case "ERROR: JSMN_ERROR_NOMEM":
		return errors.New("not enough tokens were provided")
	case "PARSER ERROR: JSMN_ERROR_INVAL":
		return errors.New("unexpected character in JSON string")
	case "PARSER ERROR: JSMN_ERROR_PART":
		return errors.New("the JSON string is not complete")
	case "":
		return originalErr
	default:
		return fmt.Errorf("ledger error: %s", responseMsg)
	}
}
