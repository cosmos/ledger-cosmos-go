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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionInfo_String(t *testing.T) {
	version := VersionInfo{AppMode: 0, Major: 1, Minor: 2, Patch: 3}
	assert.Equal(t, "1.2.3", version.String())
}

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name     string
		current  VersionInfo
		required VersionInfo
		wantErr  bool
	}{
		{
			name:     "exact match",
			current:  VersionInfo{Major: 2, Minor: 1, Patch: 0},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "higher major version",
			current:  VersionInfo{Major: 3, Minor: 0, Patch: 0},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "higher minor version",
			current:  VersionInfo{Major: 2, Minor: 2, Patch: 0},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "higher patch version",
			current:  VersionInfo{Major: 2, Minor: 1, Patch: 5},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  false,
		},
		{
			name:     "lower major version",
			current:  VersionInfo{Major: 1, Minor: 5, Patch: 0},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  true,
		},
		{
			name:     "lower minor version",
			current:  VersionInfo{Major: 2, Minor: 0, Patch: 5},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 0},
			wantErr:  true,
		},
		{
			name:     "lower patch version",
			current:  VersionInfo{Major: 2, Minor: 1, Patch: 0},
			required: VersionInfo{Major: 2, Minor: 1, Patch: 5},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckVersion(tt.current, tt.required)
			if tt.wantErr {
				assert.Error(t, err)
				var versionErr *VersionRequiredError
				assert.ErrorAs(t, err, &versionErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetBip32bytes(t *testing.T) {
	tests := []struct {
		name        string
		path        []uint32
		hardenCount int
		wantHex     string
		wantErr     error
	}{
		{
			name:        "no hardened elements",
			path:        []uint32{44, 100, 0, 0, 0},
			hardenCount: 0,
			wantHex:     "2c00000064000000000000000000000000000000",
			wantErr:     nil,
		},
		{
			name:        "two hardened elements",
			path:        []uint32{44, 118, 0, 0, 0},
			hardenCount: 2,
			wantHex:     "2c00008076000080000000000000000000000000",
			wantErr:     nil,
		},
		{
			name:        "three hardened elements (standard cosmos)",
			path:        []uint32{44, 118, 0, 0, 0},
			hardenCount: 3,
			wantHex:     "2c00008076000080000000800000000000000000",
			wantErr:     nil,
		},
		{
			name:        "invalid path length - too short",
			path:        []uint32{44, 118, 0, 0},
			hardenCount: 3,
			wantHex:     "",
			wantErr:     ErrInvalidPathLength,
		},
		{
			name:        "invalid path length - too long",
			path:        []uint32{44, 118, 0, 0, 0, 0},
			hardenCount: 3,
			wantHex:     "",
			wantErr:     ErrInvalidPathLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetBip32bytes(tt.path, tt.hardenCount)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, 20, len(result), "path bytes should be 20 bytes")
			assert.Equal(t, tt.wantHex, hex.EncodeToString(result))
		})
	}
}

func TestVersionRequiredError(t *testing.T) {
	err := NewVersionRequiredError(
		VersionInfo{Major: 2, Minor: 1, Patch: 0},
		VersionInfo{Major: 1, Minor: 5, Patch: 0},
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "2.1.0")
	assert.Contains(t, err.Error(), "1.5.0")
}
