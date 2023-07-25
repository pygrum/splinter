package splinter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	uni "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const (
	LE = 10
	BE = 20
)

var (
	encodings = map[string]int{
		"s": 1,
		"b": 2,
		"l": 3,
	}
	fileoptions = map[string][]string{
		"common": commonExtensions,
		"script": scriptExtensions,
		"exe":    exeExtensions,
		"lib":    libExtensions,
		"macro":  macroExtensions,
	}
	fileshort = map[string]string{
		"c": "common",
		"s": "script",
		"e": "exe",
		"l": "lib",
		"m": "macro",
	}
	targetexp = map[string]string{
		"url":      `\bhttps?:\/\/[^"` + "`" + `\s]+`,
		"ipv4":     `(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3})`,
		"file":     `[^\n|\r]+?\.(?i)(?:%s)(\s|$)`,
		"path":     `(?:[a-zA-Z]\:|\\\\[^\\\/\:\*\?\<\>\|]+\\[^\\\/\:\*\?\<\>\|]*)\\(?:[^\\\/\:\*\?\<\>\|]+\\)*\w([^\\\/\:\*\?\<\>\|])*`,
		"registry": `(?i)(HKLM:|hkey_local_machine|hkcu:|software)\\(?:[^\\\s]+\\)*[^\\\s]+`,
		"email":    `[a-zA-Z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}`,
		"wallet":   `[13][a-km-zA-HJ-NP-Z1-9]{25,34}`,
	}
	targetshort = map[string]string{
		"u": "url",
		"4": "ipv4",
		"f": "file",
		"r": "registry",
		"p": "path",
		"e": "email",
		"w": "wallet",
		"h": "hex",
	}
)

type FileConf struct {
	fd                   *os.File
	readOffset           int
	endianness           int
	extractTargets       []string
	fileTargets          []string
	minStrlen, maxStrlen int
	targetexp            map[string]*regexp.Regexp
	regexFilter          *regexp.Regexp
	switches             struct {
		jsonResults, strict, pretty, aggressive bool
	}
}

func validTargets(targets, options []string, shortoptions map[string]string) (string, bool) {
	for i, t := range targets {
		var valid bool
		for _, o := range options {
			if t == o {
				valid = true
				break
			}
		}
		if !valid {
			v, ok := shortoptions[t]
			if ok {
				targets[i] = v
				continue
			}
			return t, false
		}
	}
	return "", true
}

func getExtOptions(ops map[string][]string) []string {
	var eops []string
	for k := range ops {
		eops = append(eops, k)
	}
	return eops
}

func getTarOptions(ops map[string]string) []string {
	var eops []string
	for k := range ops {
		eops = append(eops, k)
	}
	return eops
}

func Parse(file, targets, ftargets, filter string, min, max int, encoding string, strict, aggressive, jsonResults, pretty bool) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}
	tOptions := getTarOptions(targetexp)
	allTargets := strings.Split(targets, ",")
	fileTargets := strings.Split(ftargets, ",")

	tg, valid := validTargets(allTargets, tOptions, targetshort)

	if !valid {
		if tg == "all" || tg == "a" {
			allTargets = tOptions
		} else if tg == "none" || tg == "n" {
			allTargets = []string{"all"}
		} else {
			return fmt.Errorf("%s is not a valid target", tg)
		}
	}
	eOptions := getExtOptions(fileoptions)
	tg, valid = validTargets(fileTargets, eOptions, fileshort)

	if !valid {
		if tg == "all" {
			fileTargets = eOptions
		} else {
			return fmt.Errorf("%s is not a valid file type", tg)
		}
	}

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	var r *regexp.Regexp
	if len(filter) > 0 {
		r, err = regexp.Compile(filter)
		if err != nil {
			return fmt.Errorf("failed to compile regex filter: %v", err)
		}
	}
	h, ok := encodings[encoding]
	if !ok {
		return fmt.Errorf("invalid encoding specified - should be s (UTF8), l (UTF16LE) or b (UTF16BE)")
	}
	var endianness int
	if h == 3 {
		endianness = LE
	} else if h == 2 {
		endianness = BE
	} else {
		endianness = -1
	}
	if max == 0 {
		// -1 means infinite length
		max = -1
	}
	if err = start(f, allTargets, fileTargets, min, max, h, endianness, r, jsonResults, strict, aggressive, pretty); err != nil {
		return err
	}
	return nil
}

func start(f *os.File, targets, fileTargets []string, min, max, readOffset, endianness int, regex *regexp.Regexp, jsonResults, strict, aggressive, pretty bool) error {
	fd := &FileConf{
		readOffset:     readOffset,
		endianness:     endianness,
		fd:             f,
		extractTargets: targets,
		fileTargets:    fileTargets,
		minStrlen:      min,
		maxStrlen:      max,
		regexFilter:    regex,
		switches: struct {
			jsonResults bool
			strict      bool
			pretty      bool
			aggressive  bool
		}{
			jsonResults: jsonResults,
			strict:      strict,
			aggressive:  aggressive,
			pretty:      pretty,
		},
	}
	if err := fd.extract(); err != nil {
		return fmt.Errorf("analysis error: %v", err)
	}
	return nil
}

// returns map of targets and their regexes of different file types, or error
func (f *FileConf) setupFileTargets(targettype string) (map[string]*regexp.Regexp, error) {
	m := make(map[string]*regexp.Regexp)
	for _, t := range f.fileTargets {
		l, ok := fileoptions[t]
		if !ok {
			return nil, fmt.Errorf("%s: invalid file extension target", t)
		}
		f.extractTargets = append(f.extractTargets, t)
		r, err := regexp.Compile(fmt.Sprintf(targetexp[targettype], strings.Join(l, "|")))
		if err != nil {
			return nil, err
		}
		m[t] = r
	}
	return m, nil
}

func (f *FileConf) initRegexp(targets map[string]string) error {
	ctargetexp := make(map[string]*regexp.Regexp)
	// extra file targets just in case
	filetargetexp := make(map[string]*regexp.Regexp)

	for s, regexPattern := range targets {
		var included = false
		// check if specified target is valid
		for _, t := range f.extractTargets {
			if s == t {
				included = true
				break
			}
		}
		if !included {
			continue
		}
		if s == "file" {
			m, err := f.setupFileTargets(s)
			if err != nil {
				return fmt.Errorf("unable to setup file targets: %v", err)
			}
			filetargetexp = m
			var index int
			for i, e := range f.extractTargets {
				if e == "file" {
					index = i
					break
				}
			}
			f.extractTargets = append(f.extractTargets[:index], f.extractTargets[index+1:]...)
			continue
		}
		r, err := regexp.Compile(regexPattern)
		if err != nil {
			return fmt.Errorf("error compiling regex pattern: %v", err)
		}
		ctargetexp[s] = r
	}
	f.targetexp = ctargetexp
	for k, v := range filetargetexp {
		f.targetexp[k] = v
	}
	return nil
}
func newUTF16Reader(file *os.File, endianness int) (*transform.Reader, error) {
	var win16enc encoding.Encoding
	if endianness == BE {
		win16enc = uni.UTF16(uni.BigEndian, uni.IgnoreBOM)
	} else {
		win16enc = uni.UTF16(uni.LittleEndian, uni.IgnoreBOM)
	}
	utf16bom := uni.BOMOverride(win16enc.NewDecoder())

	unicodeReader := transform.NewReader(file, utf16bom)
	return unicodeReader, nil
}

func (f *FileConf) validData(b byte) bool {
	return utf8.Valid([]byte{b}) && unicode.IsPrint(rune(b))
}

func (f *FileConf) extract() error {
	categories := make(map[string][]string)
	var reader *bufio.Reader
	if f.endianness != -1 {
		r, err := newUTF16Reader(f.fd, f.endianness)
		if err != nil {
			return err
		}
		reader = bufio.NewReader(r)
	} else {
		reader = bufio.NewReader(f.fd)
	}
	if err := f.initRegexp(targetexp); err != nil {
		return err
	}
	for {
		var strBytes []byte
		var fend, reading bool
		for {
			b, err := reader.ReadByte()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					fend = true
					break
				}
				return err
			}
			if !f.validData(b) {
				if reading {
					reading = false
					break
				}
				continue
			} else {
				strBytes = append(strBytes, b)
			}
			reading = true
		}
		if fend {
			break
		}
		strData := string(strBytes)
		if len(strData) < f.minStrlen || (len(strData) > f.maxStrlen && f.maxStrlen != -1) {
			continue
		}
		// filter out if matches with regex filter
		if f.regexFilter != nil {
			if validstr := f.regexFilter.MatchString(strData); !validstr {
				continue
			}
		}
		if err := f.analyse(strData, &categories); err != nil {
			return err
		}
	}
	if f.switches.pretty {
		f.pretty(&categories)
	}
	if f.switches.jsonResults {
		if err := f.json(&categories); err != nil {
			return fmt.Errorf("could not print json: %v", err)
		}
	}
	return nil
}

func (f *FileConf) pretty(categories *map[string][]string) {
	for category, data := range *categories {
		var maxlen = len(category)
		for i := 0; i < len(data); i++ {
			data[i] = strings.ReplaceAll(data[i], "%", "%%")
			if len(category+": "+data[i]) > maxlen {
				maxlen = len(category + ": " + data[i])
			}
		}
		header := " " + strings.Repeat("=", maxlen+2) + " \n"
		title := "| " + category + strings.Repeat(" ", maxlen-len(category)) + " |\n"
		fmt.Printf(header + title)
		var length int
		var first = true
		for _, d := range data {
			d = category + ": " + d
			row := "| " + d + strings.Repeat(" ", maxlen-len(d)+strings.Count(d, "%%")) + " |\n"
			length = len(row) - 3 - strings.Count(d, "%%")
			rchar := "-"
			if first {
				rchar = "="
				first = false
			}
			rowhead := " " + strings.Repeat(rchar, length) + " \n"
			fmt.Printf(rowhead + row)
		}
		fmt.Println(" " + strings.Repeat("=", length) + " \n")
	}
}

func (f *FileConf) analyse(str string, categories *map[string][]string) error {
	for _, t := range f.extractTargets {
		var matches []string
		// don't use regex for 'all' to save time
		if t == "all" {
			matches = []string{str}
		} else {
			matches = f.targetexp[t].FindAllString(str, -1)
		}
		if len(matches) == 0 {
			continue
		}
		for i := range matches {
			matches[i] = strings.TrimSpace(matches[i])
		}
		if f.switches.strict {
			if !f.switches.jsonResults && !f.switches.pretty {
				fmt.Println(str)
			}
		} else {
			for _, m := range matches {
				if len(m) < f.minStrlen || (len(m) > f.maxStrlen && f.maxStrlen != -1) {
					continue
				}
				if !f.switches.jsonResults && !f.switches.pretty {
					fmt.Println(m)
				}
			}
		}
		if f.switches.jsonResults || f.switches.pretty {
			for _, m := range matches {
				if len(m) < f.minStrlen || (len(m) > f.maxStrlen && f.maxStrlen != -1) {
					continue
				}
				if !f.switches.strict {
					(*categories)[t] = append((*categories)[t], m)
				}
			}
			if f.switches.strict {
				(*categories)[t] = append((*categories)[t], str)
			}
		}
		if !f.switches.aggressive {
			break
		}
	}
	return nil
}

func (f *FileConf) json(c *map[string][]string) error {
	json, err := json.MarshalIndent(*c, "", "\t")
	if err != nil {
		return err
	}
	fmt.Println(string(json))
	return nil
}
