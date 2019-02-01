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
	"math"

	"github.com/zondax/ledger-go"
)

const (
	validatorCLA = 0x56

	validatorINSGetVersion       = 0
	validatorINSPublicKeyED25519 = 1
	validatorINSSignED25519      = 2

	validator_MessageChunkSize = 250
)

// Validator app
type LedgerCosmosValidator struct {
	// Add support for this app
	api *ledger_go.Ledger
}

func FindLedgerCosmosValidatorApp() (*LedgerCosmosValidator, error) {
	ledgerApi, err := ledger_go.FindLedger()

	if err != nil {
		return nil, err
	}

	ledgerCosmosValidatorApp := LedgerCosmosValidator{ledgerApi}

	appVersion, err := ledgerCosmosValidatorApp.GetVersion()

	if err != nil {
		return nil, err
	}

	if appVersion.Major < RequiredVersionMajor {
		return nil, fmt.Errorf("Version not supported")
	}

	return &ledgerCosmosValidatorApp, err
}

func (ledger *LedgerCosmosValidator) GetVersion() (*VersionInfo, error) {
	message := []byte{validatorCLA, validatorINSGetVersion, 0, 0, 0}
	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, fmt.Errorf("invalid response")
	}

	return &VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}, nil
}

func (ledger *LedgerCosmosValidator) GetPublicKeyED25519(bip32_path []uint32) ([]byte, error) {
	pathBytes, err := getBip32bytes(bip32_path, 10)
	if err != nil {
		return nil, err
	}

	header := []byte{validatorCLA, validatorINSPublicKeyED25519, 0, 0, byte(len(pathBytes))}
	message := append(header, pathBytes...)

	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, fmt.Errorf("invalid response. Too short")
	}

	return response, nil
}

func (ledger *LedgerCosmosValidator) SignED25519(bip32_path []uint32, message []byte) ([]byte, error) {
	var packetIndex byte = 1
	var packetCount byte = 1 + byte(math.Ceil(float64(len(message))/float64(userMessageChunkSize)))

	var finalResponse []byte

	var apduMessage []byte

	for packetIndex <= packetCount {
		chunk := userMessageChunkSize
		if packetIndex == 1 {
			pathBytes, err := getBip32bytes(bip32_path, 10)
			if err != nil {
				return nil, err
			}
			header := []byte{
				validatorCLA,
				validatorINSSignED25519,
				packetIndex,
				packetCount,
				byte(len(pathBytes))}

			apduMessage = append(header, pathBytes...)
		} else {
			if len(message) < userMessageChunkSize {
				chunk = len(message)
			}
			header := []byte{
				validatorCLA,
				validatorINSSignED25519,
				packetIndex,
				packetCount,
				byte(chunk)}

			apduMessage = append(header, message[:chunk]...)
		}

		response, err := ledger.api.Exchange(apduMessage)
		if err != nil {
			return nil, err
		}

		finalResponse = response
		if packetIndex > 1 {
			message = message[chunk:]
		}
		packetIndex++

	}
	return finalResponse, nil
}
