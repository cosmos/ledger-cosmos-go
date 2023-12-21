/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
)

func Test_PrintVersion(t *testing.T) {
	reqVersion := VersionResponse{0, 1, 2, 3, 0, 0x12345678}
	s := fmt.Sprintf("%v", reqVersion)
	assert.Equal(t, "1.2.3", s)

	reqVersion = VersionResponse{0, 0, 0, 0, 0, 0}
	s = fmt.Sprintf("%v", reqVersion)
	assert.Equal(t, "0.0.0", s)
}

func Test_SerializePath0(t *testing.T) {
	path := "m/44'/100'/0/0/0"
	pathBytes, err := serializePath(path)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("Path: %x\n", pathBytes)

	assert.Equal(
		t,
		20,
		len(pathBytes),
		"PathBytes has wrong length: %x, expected length: %x\n", pathBytes, 20)

	assert.Equal(
		t,
		"2c00008064000080000000000000000000000000",
		fmt.Sprintf("%x", pathBytes),
		"Unexpected PathBytes\n")
}

func Test_SerializePath_EmptyString(t *testing.T) {
	path := ""
	pathBytes, err := serializePath(path)

	assert.NotNil(t, err, "Expected error for empty path, got nil")
	assert.Nil(t, pathBytes, "Expected nil for pathBytes, got non-nil value")
}

func Test_SerializePath_InvalidPath(t *testing.T) {
	path := "invalid_path"
	pathBytes, err := serializePath(path)

	assert.NotNil(t, err, "Expected error for invalid path, got nil")
	assert.Nil(t, pathBytes, "Expected nil for pathBytes, got non-nil value")
}

func Test_SerializePath1(t *testing.T) {
	path := "m/44'/118'/0'/0/0"
	pathBytes, err := serializePath(path)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("Path: %x\n", pathBytes)

	assert.Equal(
		t,
		20,
		len(pathBytes),
		"PathBytes has wrong length: %x, expected length: %x\n", pathBytes, 20)

	assert.Equal(
		t,
		"2c00008076000080000000800000000000000000",
		fmt.Sprintf("%x", pathBytes),
		"Unexpected PathBytes\n")
}

func Test_SerializePath2(t *testing.T) {
	path := "m/44'/60'/0'/0/0"
	pathBytes, err := serializePath(path)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("Path: %x\n", pathBytes)

	assert.Equal(
		t,
		20,
		len(pathBytes),
		"PathBytes has wrong length: %x, expected length: %x\n", pathBytes, 20)

	assert.Equal(
		t,
		"2c0000803c000080000000800000000000000000",
		fmt.Sprintf("%x", pathBytes),
		"Unexpected PathBytes\n")
}

func Test_SerializeHRP0(t *testing.T) {
	hrp := "cosmos"
	hrpBytes, err := serializeHRP(hrp)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("HRP: %x\n", hrpBytes)

	assert.Equal(
		t,
		6,
		len(hrpBytes),
		"hrpBytes has wrong length: %x, expected length: %x\n", hrpBytes, 6)

	assert.Equal(
		t,
		"636f736d6f73",
		fmt.Sprintf("%x", hrpBytes),
		"Unexpected HRPBytes\n")
}

func Test_SerializeHRP_EmptyString(t *testing.T) {
	hrp := ""
	hrpBytes, err := serializeHRP(hrp)

	assert.NotNil(t, err, "Expected error for empty hrp, got nil")
	assert.Nil(t, hrpBytes, "Expected nil for hrpBytes, got non-nil value")
}

func Test_SerializeHRP_LongString(t *testing.T) {
	hrp := "a_very_long_hrp_that_exceeds_the_maximum_length"
	hrpBytes, err := serializeHRP(hrp)

	assert.NotNil(t, err, "Expected error for long hrp, got nil")
	assert.Nil(t, hrpBytes, "Expected nil for hrpBytes, got non-nil value")
}

func Test_SerializeHRP1(t *testing.T) {
	hrp := "evmos"
	hrpBytes, err := serializeHRP(hrp)

	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("HRP: %x\n", hrpBytes)

	assert.Equal(
		t,
		5,
		len(hrpBytes),
		"hrpBytes has wrong length: %x, expected length: %x\n", hrpBytes, 5)

	assert.Equal(
		t,
		"65766d6f73",
		fmt.Sprintf("%x", hrpBytes),
		"Unexpected HRPBytes\n")
}
