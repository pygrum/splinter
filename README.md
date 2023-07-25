# Splinter
## Comprehensive file strings analyzer

`splinter` is a version of the `strings` utility weaponized for malware analysis.

`splinter` aids with basic static analysis, with the ability to:
- quickly extract specific string types from a binary - URLs, IPs, registry keys, files, filetypes, and more
- apply global regex filters over extracted strings to further narrow down the output for desired results
- export the extraction results to a json file, where strings are categorized by their type
- pretty print the results in neat, fitted tables

Installation is easy: run `make` to build the `splinter` binary.
You can find the Windows builds on the [releases page](https://github.com/pygrum/splinter/releases).

### Target descriptions

```
usage: splinter [<flags>] <file>

cli tool for comprehensive analysis of file strings

Flags:
  -h, --help             Show context-sensitive help (also try --help-long and --help-man).
  -t, --targets="all"    string types to extract {[u]rl ipv[4] [r]egistry [p]ath [f]ile [e]mail [w]allet [n]one [a]ll} (comma-separated). 'none' extracts any printable characters (like 'strings')
  -f, --filetypes="all"  specific filetypes to extract {[c]ommon [s]cript [e]xe [l]ib [m]acro [a]ll}. exe - executables. macro - macro enabled office files. lib - shared libraries
      --max=MAX          maximum extractable string length
      --min=4            minimum extractable string length
  -j, --json             print results in json format
      --filter=FILTER    regex filter for all strings before extraction (like 'grep')
  -s, --nostrict         if target is found, print the entire string that it was found in
  -e, --encoding="s"     file encoding format (UTF8=s, UTF16LE=l, UTF16BE=b)
  -p, --pretty           pretty print results (in category tables)
      --agg              attempt to find matches for every target in each string (aggressive mode)

Args:
  <file>  name of file to analyze - (executable / image)
```
| Option | Description |
| --- | ------------- |
| `url` | Extract embedded URLs. This works by matching strings that contain `http(s)://` and no other invalid characters. As of v0.1.3, there's no support for other directives such as `ssh` or `ftp`. |
| `ipv4` | Extract ipv4 addresses. Any valid ({0-255}.{0-255}.{0-255}.{0-255}) IPv4 addresses are matched. As of v0.1.3, there's no support for IPv6 addresses. |
| `registry` | Matches any paths that begin with HKLM:\ or HKEY_LOCAL_MACHINE. |
| `path` | Extract windows paths - typically a single ascii letter + :\ + text |
| `file` | Matches any string that contains a valid (case insensitive) file extension. The 'file type descriptions' heading describes specific filetypes that users can search for. |
| `email` | Matches valid email addresses. |
| `wallet` | Matches valid Bitcoin addresses. |
| `none` | `splinter` will act as the default `strings` utility. |
| `all` | Extract all of the special targets above. | 

#### File type descriptions

| Option | Description |
| --- | ------------- |
| `common` | Extract files by common file extensions (e.g. docx, pdf, jpg) |
| `script` | Extract (what are believed to be) embedded script names (e.g. py, js, sh, ps1) |
| `exe` | Extract executables by common executable file extensions (e.g. exe, apk) |
| `lib` | Extract shared libraries (e.g. dll, so, dylib) |
| `macro` | Extract macro-enabled Microsoft Office documents (e.g. docm, xlm, pptm) |
| `all` | extract all of the special targets above. |

## Disclaimer

I have tried to the best of my ability to make this tool accurate and useful. However, it is designed for use during *basic* static analysis.  
There may be certain binaries that cause more false positives - an example being the number of false positive wallet addresses when analysing a Golang binary, due to the number of valid address strings that may appear within the file. In this scenario, more advanced static analysis would be the best choice.

Note: I do not condone the illegitimate use of this tool.