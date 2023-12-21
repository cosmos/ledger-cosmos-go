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
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type VersionResponse struct {
	AppMode   uint8 // 0: release | 0xFF: debug
	Major     uint8
	Minor     uint8
	Patch     uint8
	AppLocked uint8
	TargetId  uint32
}

type AddressResponse struct {
	pubkey  []byte
	address string
}

type SignatureResponse struct {
	signatureDER []byte
}

func (c VersionResponse) String() string {
	return fmt.Sprintf("%d.%d.%d", c.Major, c.Minor, c.Patch)
}

// Validate HRP: Max length = 83
// All characters must be in range [33, 126], displayable chars in Ledger devices
func serializeHRP(hrp string) (hrpBytes []byte, err error) {
	if len(hrp) > HRP_MAX_LENGTH {
		return nil, errors.New("HRP len should be <= 83")
	}

	hrpBytes = []byte(hrp)
	for _, b := range hrpBytes {
		if b < MIN_DISPLAYABLE_CHAR || b > MAX_DISPLAYABLE_CHAR {
			return nil, errors.New("all characters in the HRP must be in the [33, 126] range")
		}
	}

	return hrpBytes, nil
}

func serializePath(path string) (pathBytes []byte, err error) {
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New(`path should start with "m/" (e.g "m/44'/118'/0'/0/3")`)
	}

	pathArray := strings.Split(path, "/")
	pathArray = pathArray[1:] // remove "m"

	if len(pathArray) != DEFAULT_PATH_LENGTH {
		return nil, errors.New("invalid path: it must contain 5 elements")
	}

	// Reserve 20 bytes for serialized path
	buffer := make([]byte, 4*len(pathArray))

	for i, child := range pathArray {
		value := 0
		if strings.HasSuffix(child, "'") {
			value += HARDENED
			child = strings.TrimSuffix(child, "'")
		}
		numChild, err := strconv.Atoi(child)
		if err != nil {
			return nil, fmt.Errorf("invalid path : %s is not a number (e.g \"m/44'/118'/0'/0/3\")", child)
		}
		if numChild >= HARDENED {
			return nil, errors.New("incorrect child value (bigger or equal to 0x80000000)")
		}
		value += numChild
		binary.LittleEndian.PutUint32(buffer[i*4:], uint32(value))
	}
	return buffer, nil
}
