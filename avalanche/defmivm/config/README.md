# Genesis configuration

`test-genesis.json` is deterministic test material only. Its private seeds are
intentionally recoverable from the interoperability tests and it must never be
used on Fuji, Mainnet or a production L1.

Production setup exports only the seven public signing keys from the encrypted
QOMM key stores and compiles them with the Rust VM binary:

```sh
qomm-avalanche-vm genesis --config production-genesis.json --out genesis.bin
```

The compiler rejects unknown JSON fields, invalid widths, duplicate node IDs,
an impossible threshold and trailing data. The resulting binary is the exact
genesis byte string supplied to every Avalanche validator.
