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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PrintVersion(t *testing.T) {
	reqVersion := VersionInfo{0, 1, 2, 3}
	s := fmt.Sprintf("%v", reqVersion)
	assert.Equal(t, "1.2.3", s)
}

func Test_PathGeneration(t *testing.T) {
	tests := []struct {
		name         string
		bip32Path    []uint32
		hardenCount  int
		expectedPath string
	}{
		{
			name:         "PathGeneration0",
			bip32Path:    []uint32{44, 100, 0, 0, 0},
			hardenCount:  0,
			expectedPath: "052c000000640000000000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:         "PathGeneration2",
			bip32Path:    []uint32{44, 118, 0, 0, 0},
			hardenCount:  2,
			expectedPath: "052c000080760000800000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:         "PathGeneration3",
			bip32Path:    []uint32{44, 118, 0, 0, 0},
			hardenCount:  3,
			expectedPath: "052c000080760000800000008000000000000000000000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathBytes, err := GetBip32bytesv1(tt.bip32Path, tt.hardenCount)
			require.NoError(t, err, "Detected error")

			fmt.Printf("Path: %x\n", pathBytes)

			assert.Equal(t, 41, len(pathBytes), "PathBytes has wrong length: %x, expected length: %x\n", pathBytes, 41)
			assert.Equal(t, tt.expectedPath, fmt.Sprintf("%x", pathBytes), "Unexpected PathBytes\n")
		})
	}
}

func Test_CheckVersion(t *testing.T) {
	tests := []struct {
		name            string
		currentVersion  *VersionInfo
		requiredVersion VersionInfo
		expectError     bool
	}{
		{
			name:            "VersionCheckPass",
			currentVersion:  &VersionInfo{0, 2, 1, 0},
			requiredVersion: VersionInfo{0, 2, 0, 0},
			expectError:     false,
		},
		{
			name:            "VersionCheckFail",
			currentVersion:  &VersionInfo{0, 2, 1, 0},
			requiredVersion: VersionInfo{0, 2, 1, 1},
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckVersion(tt.currentVersion, tt.requiredVersion)
			if tt.expectError {
				require.Error(t, err, "Version check passed when it should have failed")
			} else {
				require.NoError(t, err, "Version check failed when it should have passed")
			}
		})
	}
}

func Test_InvalidHRPByte(t *testing.T) {
	tests := []struct {
		byteValue     byte
		expectInvalid bool
	}{
		{32, true},
		{33, false},
		{126, false},
		{127, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("ByteValue%d", tt.byteValue), func(t *testing.T) {
			assert.Equal(t, tt.expectInvalid, invalidHRPByte(tt.byteValue), "Unexpected result for byte %d", tt.byteValue)
		})
	}
}
