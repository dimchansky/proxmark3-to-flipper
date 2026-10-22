# proxmark3-to-flipper
`proxmark3-to-flipper` is a tool that converts Mifare Classic JSON dump files into [FlipperZero's](https://flipperzero.one/) custom .nfc format.

## Usage

```
proxmark3-to-flipper -i dump.json -o card.nfc [-force]
```

An existing output file is never replaced unless `-force` is given, and the
output may not be the input file. See [docs/output-safety.md](docs/output-safety.md).

Accepted inputs are Proxmark3 MIFARE Classic dumps (`mfcard`, `mfc v2`,
`mfc v3`) of Mini, 1K and 4K cards; see [docs/conversion.md](docs/conversion.md)
for what is validated, rejected and not converted.
