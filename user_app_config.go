//go:build !ledger_zemu
// +build !ledger_zemu

package ledger_cosmos_go

const (
	cosmosAppNotOpenErrorMessage = "are you sure the Cosmos app is open?"
	ledgerDeviceType             = "Ledger Nano S device"
	findDeviceDescription        = "finds a Cosmos user app running in a ledger device"
)
