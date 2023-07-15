# Splinter
## Comprehensive file strings analyzer

`splinter` is a version of the `strings` utility weaponized for malware analysis.

`splinter` aids with basic static analysis, with its ability to quickly extract specific string types from a binary - URLs, IPs, registry keys and more.  
Users have the ability to apply regex filters over extracted strings to further narrow down the output for their desired results.  
It's also possible to write the extraction results to a json file, where strings are categorised by their type.

Installation is easy: run `make` to build the `splinter` binary.
You can find the Windows builds on the [releases page](https://github.com/pygrum/splinter/releases).