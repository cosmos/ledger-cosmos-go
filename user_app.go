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
	userCLA = 0x55

	userINSGetVersion         = 0
	userINSPublicKeySECP256K1 = 1
	userINSSignSECP256K1      = 2

	userINSHash                   = 100
	userINSPublicKeySECP256K1Test = 101
	userINSSignSECP256K1Test      = 103

	userMessageChunkSize = 250

	RequiredVersionMajor = 1
	RequiredVersionMinor = 0
	RequiredVersionPatch = 0
)

// LedgerCosmos represents a connection to the Cosmos app in a Ledger Nano S device
type LedgerCosmos struct {
	api *ledger_go.Ledger
}

// FindLedgerCosmosUserApp finds a Cosmos app running in a device
func FindLedgerCosmosUserApp() (*LedgerCosmos, error) {
	ledgerApi, err := ledger_go.FindLedger()

	if err != nil {
		return nil, err
	}

	ledgerCosmosUserApp := LedgerCosmos{ledgerApi}

	appVersion, err := ledgerCosmosUserApp.GetVersion()

	if err != nil {
		return nil, err
	}

	if appVersion.Major < RequiredVersionMajor {
		return nil, fmt.Errorf("version not supported")
	}

	return &ledgerCosmosUserApp, err
}

func (ledger *LedgerCosmos) Close() error {
	return ledger.api.Close()
}

func (ledger *LedgerCosmos) GetVersion() (*VersionInfo, error) {
	message := []byte{userCLA, userINSGetVersion, 0, 0, 0}
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

func (ledger *LedgerCosmos) sign(instruction byte, bip32_path []uint32, transaction []byte) ([]byte, error) {
	var packetIndex byte = 1
	var packetCount byte = 1 + byte(math.Ceil(float64(len(transaction))/float64(userMessageChunkSize)))

	var finalResponse []byte

	var message []byte

	for packetIndex <= packetCount {
		chunk := userMessageChunkSize
		if packetIndex == 1 {
			pathBytes, err := getBip32bytes(bip32_path, 3)
			if err != nil {
				return nil, err
			}
			header := []byte{userCLA, instruction, packetIndex, packetCount, byte(len(pathBytes))}
			message = append(header, pathBytes...)
		} else {
			if len(transaction) < userMessageChunkSize {
				chunk = len(transaction)
			}
			header := []byte{userCLA, instruction, packetIndex, packetCount, byte(chunk)}
			message = append(header, transaction[:chunk]...)
		}

		response, err := ledger.api.Exchange(message)
		if err != nil {
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

func (ledger *LedgerCosmos) SignSECP256K1(bip32_path []uint32, transaction []byte) ([]byte, error) {
	return ledger.sign(userINSSignSECP256K1, bip32_path, transaction)
}

func (ledger *LedgerCosmos) GetPublicKeySECP256K1(bip32_path []uint32) ([]byte, error) {
	pathBytes, err := getBip32bytes(bip32_path, 3)
	if err != nil {
		return nil, err
	}
	header := []byte{userCLA, userINSPublicKeySECP256K1, 0, 0, byte(len(pathBytes))}
	message := append(header, pathBytes...)

	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, fmt.Errorf("invalid response")
	}

	return response, nil
}

func (ledger *LedgerCosmos) Hash(transaction []byte) ([]byte, error) {

	var packetIndex = byte(1)
	var packetCount = byte(math.Ceil(float64(len(transaction)) / float64(userMessageChunkSize)))

	var finalResponse []byte
	for packetIndex <= packetCount {
		chunk := userMessageChunkSize
		if len(transaction) < userMessageChunkSize {
			chunk = len(transaction)
		}

		header := []byte{userCLA, userINSHash, packetIndex, packetCount, byte(chunk)}
		message := append(header, transaction[:chunk]...)
		response, err := ledger.api.Exchange(message)

		if err != nil {
			return nil, err
		}
		finalResponse = response
		packetIndex++
		transaction = transaction[chunk:]
	}
	return finalResponse, nil
}

func (ledger *LedgerCosmos) TestGetPublicKeySECP256K1() ([]byte, error) {
	message := []byte{userCLA, userINSPublicKeySECP256K1Test, 0, 0, 0}
	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, fmt.Errorf("invalid response")
	}

	return response, nil
}

func (ledger *LedgerCosmos) TestSignSECP256K1(transaction []byte) ([]byte, error) {
	var packetIndex byte = 1
	var packetCount byte = byte(math.Ceil(float64(len(transaction)) / float64(userMessageChunkSize)))

	var finalResponse []byte

	for packetIndex <= packetCount {

		chunk := userMessageChunkSize
		if len(transaction) < userMessageChunkSize {
			chunk = len(transaction)
		}

		header := []byte{userCLA, userINSSignSECP256K1Test, packetIndex, packetCount, byte(chunk)}
		message := append(header, transaction[:chunk]...)

		response, err := ledger.api.Exchange(message)

		if err != nil {
			return nil, err
		}

		finalResponse = response
		packetIndex++
		transaction = transaction[chunk:]
	}
	return finalResponse, nil
}
