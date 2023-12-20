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

type TxMode byte

const (
	SignModeAmino   TxMode = 0
	SignModeTextual TxMode = 1
	SignModeUnknown TxMode = 2
)

const (
	CLA = 0x55

	INSGetVersion          = 0
	INSSign                = 2
	INSGetAddressAndPubKey = 4

	CHUNKSIZE = 250

	DEFAULT_PATH_LENGTH = 5
)

const (
	HRP_MAX_LENGTH       = 83
	MIN_DISPLAYABLE_CHAR = 33
	MAX_DISPLAYABLE_CHAR = 126
	HARDENED             = 0x80000000
)
