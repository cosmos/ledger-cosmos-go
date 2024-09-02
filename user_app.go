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
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	ledger_go "github.com/zondax/ledger-go"
)

const (
	userCLA = 0x55

	userINSGetVersion       = 0
	userINSSignSECP256K1    = 2
	userINSGetAddrSecp256k1 = 4

	userMessageChunkSize = 250
)

// LedgerCosmos represents a connection to the Cosmos app in a Ledger Nano S device
type LedgerCosmos struct {
	api ledger_go.LedgerDevice
}

// CheckVersion returns an error if the App version is not supported by this library
func (ledger *LedgerCosmos) CheckVersion() error {
	version, err := ledger.GetVersion()
	if err != nil {
		return err
	}

	requiredVersion := VersionInfo{0, 2, 1, 0}
	return CheckVersion(version, requiredVersion)
}

// FindLedgerCosmosUserApp finds a Cosmos user app running in a ledger device
func FindLedgerCosmosUserApp() (*LedgerCosmos, error) {
	ledgerAdmin := ledger_go.NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ledger device: %w", err)
	}
	defer func() {
		if err != nil {
			ledgerAPI.Close()
		}
	}()

	app := &LedgerCosmos{api: ledgerAPI}
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] Class not supported" {
			return nil, errors.New("please ensure the Cosmos app is open")
		}
		return nil, fmt.Errorf("failed to get app version: %w", err)
	}

	if err := app.CheckVersion(); err != nil {
		return nil, fmt.Errorf("app version check failed: %w", err)
	}

	return app, nil
}

// Close closes a connection with the Cosmos user app
func (ledger *LedgerCosmos) Close() error {
	return ledger.api.Close()
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

	return &VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}, nil
}

// SignSECP256K1 signs a transaction using Cosmos user app. It can either use
// SIGN_MODE_LEGACY_AMINO_JSON (P2=0) or SIGN_MODE_TEXTUAL (P2=1).
// this command requires user confirmation in the device
func (ledger *LedgerCosmos) SignSECP256K1(bip32Path []uint32, transaction []byte, p2 byte) ([]byte, error) {
	var packetIndex byte = 1
	var packetCount = 1 + byte(math.Ceil(float64(len(transaction))/float64(userMessageChunkSize)))

	var finalResponse []byte

	var message []byte

	if p2 > 1 {
		return nil, errors.New("only values of SIGN_MODE_LEGACY_AMINO (P2=0) and SIGN_MODE_TEXTUAL (P2=1) are allowed")
	}

	for packetIndex <= packetCount {
		chunk := userMessageChunkSize
		if packetIndex == 1 {
			pathBytes, err := ledger.GetBip32bytes(bip32Path, 3)
			if err != nil {
				return nil, err
			}
			header := []byte{userCLA, userINSSignSECP256K1, 0, p2, byte(len(pathBytes))}
			message = append(header, pathBytes...)
		} else {
			if len(transaction) < userMessageChunkSize {
				chunk = len(transaction)
			}

			payloadDesc := byte(1)
			if packetIndex == packetCount {
				payloadDesc = byte(2)
			}

			header := []byte{userCLA, userINSSignSECP256K1, payloadDesc, p2, byte(chunk)}
			message = append(header, transaction[:chunk]...)
		}

		response, err := ledger.api.Exchange(message)
		if err != nil {
			if err.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
				// In this special case, we can extract additional info
				errorMsg := string(response)
				switch errorMsg {
				case "ERROR: JSMN_ERROR_NOMEM":
					return nil, errors.New("not enough tokens were provided")
				case "PARSER ERROR: JSMN_ERROR_INVAL":
					return nil, errors.New("unexpected character in JSON string")
				case "PARSER ERROR: JSMN_ERROR_PART":
					return nil, errors.New("the JSON string is not a complete")
				}
				return nil, errors.New(errorMsg)
			}
			if err.Error() == "[APDU_CODE_DATA_INVALID] referenced data reversibly blocked (invalidated)" {
				errorMsg := string(response)
				return nil, errors.New(errorMsg)
			}
			return nil, err
		}

		finalResponse = response
		if packetIndex > 1 {
			transaction = transaction[chunk:]
		}
		packetIndex++

	}
	return finalResponse, nil

}

// GetPublicKeySECP256K1 retrieves the public key for the corresponding bip32 derivation path (compressed)
// this command DOES NOT require user confirmation in the device
func (ledger *LedgerCosmos) GetPublicKeySECP256K1(bip32Path []uint32) ([]byte, error) {
	pubkey, _, err := ledger.getAddressPubKeySECP256K1(bip32Path, "cosmos", false)
	return pubkey, err
}

// GetAddressPubKeySECP256K1 returns the public key (compressed) and address (bech32 format)
// This command requires user confirmation on the device.
func (ledger *LedgerCosmos) GetAddressPubKeySECP256K1(bip32Path []uint32, hrp string) ([]byte, string, error) {
	return ledger.getAddressPubKeySECP256K1(bip32Path, hrp, true)
}

func (ledger *LedgerCosmos) GetBip32bytes(bip44Path []uint32, hardenCount int) ([]byte, error) {
	message := make([]byte, 20)

	if len(bip44Path) != 5 {
		return nil, fmt.Errorf("path should contain 5 elements")
	}

	for index, element := range bip44Path {
		pos := index * 4
		value := element
		if index < 3 {
			value = 0x80000000 | element
		}
		binary.LittleEndian.PutUint32(message[pos:], value)
	}
	return message, nil
}

// GetAddressPubKeySECP256K1 returns the pubkey (compressed) and address (bech(
// this command requires user confirmation in the device
func (ledger *LedgerCosmos) getAddressPubKeySECP256K1(bip32Path []uint32, hrp string, requireConfirmation bool) (pubkey []byte, addr string, err error) {
	if len(hrp) == 0 || len(hrp) > 83 {
		return nil, "", errors.New("hrp length must be between 1 and 83 characters")
	}

	hrpBytes := []byte(hrp)
	for _, b := range hrpBytes {
		if invalidHRPByte(b) {
			return nil, "", errors.New("all characters in the HRP must be in the [33, 126] range")
		}
	}

	pathBytes, err := ledger.GetBip32bytes(bip32Path, 3)
	if err != nil {
		return nil, "", err
	}

	p1 := byte(0)
	if requireConfirmation {
		p1 = 1
	}

	// Prepare message
	header := []byte{userCLA, userINSGetAddrSecp256k1, p1, 0, 0}

	message := append(header, byte(len(hrpBytes)))
	message = append(message, hrpBytes...)
	message = append(message, pathBytes...)
	message[4] = byte(len(message) - len(header)) // update length

	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, "", fmt.Errorf("failed to exchange message: %w", err)
	}
	if len(response) < 35+len(hrp) {
		return nil, "", fmt.Errorf("invalid response length: expected at least %d, got %d", 35+len(hrp), len(response))
	}

	pubkey = response[0:33]
	addr = string(response[33:])

	return pubkey, addr, err
}
