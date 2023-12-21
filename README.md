# ledger-cosmos-go

![zondax_light](docs/zondax_light.png#gh-light-mode-only)
![zondax_dark](docs/zondax_dark.png#gh-dark-mode-only)

[![Test](https://github.com/cosmos/ledger-cosmos-go/actions/workflows/test.yml/badge.svg)](https://github.com/cosmos/ledger-cosmos-go/actions/workflows/test.yml)
[![Build status](https://ci.appveyor.com/api/projects/status/ovpfx35t289n3403?svg=true)](https://ci.appveyor.com/project/cosmos/ledger-cosmos-go)

This package provides a basic client library to communicate with a Cosmos App running in a Ledger Nano S/S+/X device

| Operation            | Response                    | Command                          |
| -------------------- | --------------------------- | -------------------------------- |
| GetVersion           | app version                 | ---------------                  |
| GetAddressAndPubKey  | pubkey + address            | HRP + HDPath + ShowInDevice   |
| Sign                 | signature in DER format     | HDPath + HRP + SignMode* + Message  |

*Available sign modes for Cosmos app: 	SignModeAmino (0) | SignModeTextual (1)


# Who we are?

We are Zondax, a company pioneering blockchain services. If you want to know more about us, please visit us at [zondax.ch](https://zondax.ch)
