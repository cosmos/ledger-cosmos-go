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
)

const (
	// bip32PathLength is the required number of elements in a BIP32/BIP44 path
	bip32PathLength = 5

	// bip32BytesLength is the byte length of the serialized BIP32 path (5 elements * 4 bytes)
	bip32BytesLength = 20

	// hardenedOffset is the offset added to hardened path elements
	hardenedOffset = 0x80000000
)

// ErrInvalidPathLength is returned when the BIP32 path doesn't have exactly 5 elements
var ErrInvalidPathLength = errors.New("BIP32 path must contain exactly 5 elements")

// VersionInfo contains app version information.
type VersionInfo struct {
	AppMode uint8
	Major   uint8
	Minor   uint8
	Patch   uint8
}

// String returns the version as a string in the format "Major.Minor.Patch".
func (v VersionInfo) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// VersionRequiredError indicates that the app version does not meet the minimum requirements.
type VersionRequiredError struct {
	Found    VersionInfo
	Required VersionInfo
}

// Error implements the error interface for VersionRequiredError.
func (e *VersionRequiredError) Error() string {
	return fmt.Sprintf("app version required %s - version found: %s", e.Required, e.Found)
}

// NewVersionRequiredError creates a new VersionRequiredError.
func NewVersionRequiredError(required, found VersionInfo) error {
	return &VersionRequiredError{
		Found:    found,
		Required: required,
	}
}

// CheckVersion compares the current version with the required version.
// Returns nil if the current version meets or exceeds the required version.
func CheckVersion(current, required VersionInfo) error {
	if current.Major > required.Major {
		return nil
	}
	if current.Major < required.Major {
		return NewVersionRequiredError(required, current)
	}

	// Major versions are equal, check minor
	if current.Minor > required.Minor {
		return nil
	}
	if current.Minor < required.Minor {
		return NewVersionRequiredError(required, current)
	}

	// Minor versions are equal, check patch
	if current.Patch >= required.Patch {
		return nil
	}

	return NewVersionRequiredError(required, current)
}

// GetBip32bytes serializes a BIP32/BIP44 path into bytes for the Ledger device.
// The path must contain exactly 5 elements. Elements at indices less than hardenCount
// will be hardened (have 0x80000000 added to them).
func GetBip32bytes(path []uint32, hardenCount int) ([]byte, error) {
	if len(path) != bip32PathLength {
		return nil, ErrInvalidPathLength
	}

	result := make([]byte, bip32BytesLength)

	for i, element := range path {
		value := element
		if i < hardenCount {
			value |= hardenedOffset
		}
		binary.LittleEndian.PutUint32(result[i*4:], value)
	}

	return result, nil
}
