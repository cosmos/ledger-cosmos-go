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
	"errors"
	"math"

	ledger_go "github.com/zondax/ledger-go"
)

type LedgerCosmos struct {
	api     ledger_go.LedgerDevice
	version VersionResponse
}

// FindLedger finds a Cosmos user app running in a ledger device
func FindLedger() (_ *LedgerCosmos, rerr error) {
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

	app := &LedgerCosmos{ledgerAPI, VersionResponse{}}
	_, err = app.GetVersion()
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] Class not supported" {
			err = errors.New("are you sure the Cosmos app is open?")
		}
		return nil, err
	}

	return app, nil
}

func (ledger *LedgerCosmos) Close() error {
	return ledger.api.Close()
}

// GetVersion returns the current version of the Ledger Cosmos  app
func (ledger *LedgerCosmos) GetVersion() (*VersionResponse, error) {
	message := []byte{CLA, INSGetVersion, 0, 0, 0}
	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) != 9 {
		return nil, errors.New("invalid response")
	}

	ledger.version = VersionResponse{
		AppMode:   response[0],
		Major:     response[1],
		Minor:     response[2],
		Patch:     response[3],
		AppLocked: response[4], // SDK won't reply any APDU message if screensaver is active (always false)
		TargetId:  uint32(response[5]),
	}

	return &ledger.version, nil
}

// GetAddressAndPubKey  send INSGetAddressAndPubKey APDU command
// Optional parameter to display the information on the device first

// Response:
// | Field   | Type      | Content               |
// | ------- | --------- | --------------------- |
// | PK      | byte (33) | Compressed Public Key |
// | ADDR    | byte (65) | Bech 32 addr          |
// | SW1-SW2 | byte (2)  | Return code           |

// Devolver Struct + err

func (ledger *LedgerCosmos) GetAddressAndPubKey(path string, hrp string, requireConfirmation bool) (addressResponse AddressResponse, err error) {

	response := AddressResponse{
		pubkey:  nil, // Compressed pubkey
		address: "",
	}

	// Serialize HRP
	hrpBytes, err := serializeHRP(hrp)
	if err != nil {
		return response, err
	}

	// Serialize Path
	pathBytes, err := serializePath(path)
	if err != nil {
		return response, err
	}

	p1 := byte(0)
	if requireConfirmation {
		p1 = byte(1)
	}

	// Prepare message
	// [header | hrpLen | hrp | hdpath]
	header := []byte{CLA, INSGetAddressAndPubKey, p1, 0, 0}
	message := append(header, byte(len(hrpBytes)))
	message = append(message, hrpBytes...)
	message = append(message, pathBytes...)
	message[4] = byte(len(message) - len(header)) // Update payload length

	cmdResponse, err := ledger.api.Exchange(message)

	if err != nil {
		return response, err
	}

	// The command response must have 33 bytes from pubkey
	// the HRP and the rest of the address
	if 33+len(hrp) > len(cmdResponse) {
		return response, errors.New("invalid response length")
	}

	// Build response
	response.pubkey = cmdResponse[0:33] // Compressed pubkey
	response.address = string(cmdResponse[33:])

	return response, nil
}

func processFirstChunk(path string, hrp string, txMode TxMode) (message []byte, err error) {
	// Serialize hrp
	hrpBytes, err := serializeHRP(hrp)
	if err != nil {
		return nil, err
	}

	// Serialize Path
	pathBytes, err := serializePath(path)
	if err != nil {
		return nil, err
	}

	// [header | path | hrpLen | hrp]
	header := []byte{CLA, INSSign, 0, byte(txMode), 0}
	message = append(header, pathBytes...)
	message = append(message, byte(len(hrpBytes)))
	message = append(message, hrpBytes...)
	message[4] = byte(len(message) - len(header))

	return message, nil
}

func processErrorResponse(response []byte, responseErr error) (err error) {
	// Check if we can get the error code and improve these messages
	if responseErr.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
		// In this special case, we can extract additional info
		errorMsg := string(response)
		switch errorMsg {
		case "ERROR: JSMN_ERROR_NOMEM":
			return errors.New("not enough tokens were provided")
		case "PARSER ERROR: JSMN_ERROR_INVAL":
			return errors.New("unexpected character in JSON string")
		case "PARSER ERROR: JSMN_ERROR_PART":
			return errors.New("the JSON string is not a complete")
		}
		return errors.New(errorMsg)
	}
	if responseErr.Error() == "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)" {
		errorMsg := string(response)
		return errors.New(errorMsg)
	}
	return responseErr
}

func (ledger *LedgerCosmos) sign(path string, hrp string, txMode TxMode, transaction []byte) (signatureResponse SignatureResponse, err error) {
	var packetCount = byte(math.Ceil(float64(len(transaction)) / float64(CHUNKSIZE)))
	var message []byte

	signatureResponse = SignatureResponse{
		signatureDER: nil,
	}

	if txMode >= SignModeUnknown {
		return signatureResponse, errors.New("at the moment the Ledger app only works with Amino (0) and Textual(1) modes")
	}

	// First chunk only contains path & HRP
	message, err = processFirstChunk(path, hrp, txMode)
	if err != nil {
		return signatureResponse, err
	}

	_, err = ledger.api.Exchange(message)
	if err != nil {
		return signatureResponse, err
	}

	// Split the transaction in chunks
	for packetIndex := byte(1); packetIndex <= packetCount; packetIndex++ {
		chunk := CHUNKSIZE
		if len(transaction) < CHUNKSIZE {
			chunk = len(transaction)
		}

		// p1 can have 3 different values:
		// p1 = 0 INIT (first chunk)
		// p1 = 1 ADD from chunk 1 up to packetCount - 1
		// p1 = 2 LAST indicates to the app that is the last chunk
		p1 := byte(1)
		if packetIndex == packetCount {
			p1 = byte(2)
		}

		header := []byte{CLA, INSSign, p1, byte(txMode), byte(chunk)}
		message = append(header, transaction[:chunk]...)

		apduResponse, err := ledger.api.Exchange(message)
		if err != nil {
			return signatureResponse, processErrorResponse(apduResponse, err)
		}

		// Trim sent bytes
		transaction = transaction[chunk:]
		signatureResponse.signatureDER = apduResponse
	}

	// Ledger app returns the signature in DER format
	return signatureResponse, nil
}
