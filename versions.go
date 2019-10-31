package ledger_cosmos_go

// Defines cosmos & custom project app mode
const (
	appModeCosmos = 0x00
	appModeTerra  = 0x01
	appModeTest   = 0xFF
)

var (
	minSupportedVersions = []VersionInfo{
		{appModeCosmos, 1, 5, 1},
		{appModeCosmos, 2, 1, 0},
		{appModeTerra, 1, 0, 0},
	}
)
