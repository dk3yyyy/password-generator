# Built-in passphrase wordlist

`eff_large_wordlist.txt` contains the 7,776 words from the Electronic Frontier
Foundation's **EFF Large Wordlist for Passphrases**, with the five-digit dice
codes removed. The word order is unchanged.

- Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
- Source documentation: https://www.eff.org/document/passphrase-wordlists
- Retrieved: 2026-07-24
- Original source SHA-256: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- Derived words-only SHA-256: `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`
- Transformation: removed each line's tab-separated five-digit dice code

The original EFF material is attributed to the Electronic Frontier Foundation
and is distributed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/),
per [EFF's copyright policy](https://www.eff.org/copyright).

PassGen validates the bundled file at startup for its expected size, uniqueness,
and lowercase ASCII word format. The list is loaded once and shared by the CLI
and web application.
