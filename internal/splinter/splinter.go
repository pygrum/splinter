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
)

const (
	asciiMin = 0x20
	asciiMax = 0x7e
	exts
)

var (
	options   = []string{"url", "ipv4", "tag", "file", "registry"}
	targetexp = map[string]string{
		"url":      `\bhttps?:\/\/[^"` + "`" + `\s]+`,
		"ipv4":     `(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3})`,
		"tag":      `(<.*>.*<.*/?>|</?.*>)`,
		"file":     `.+?\.(?:%s)`,
		"registry": `(?i)(HKLM:|hkey_local_machine)\\(?:[^\\\s]+\\)*[^\\\s]+`,
		"all":      `.*`,
	}
)

type FileConf struct {
	fd                   *os.File
	extractTargets       []string
	minStrlen, maxStrlen int
	targetexp            map[string]*regexp.Regexp
	regexFilter          *regexp.Regexp
	switches             struct {
		saveResults, strict, pretty, aggressive bool
	}
}

func Parse(file, targets, filter string, min, max int, strict, aggressive, saveResults, pretty bool) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}

	allTargets := strings.Split(targets, ",")

	for _, t := range allTargets {
		var valid bool
		for _, o := range options {
			if t == o {
				valid = true
				break
			}
		}
		if !valid {
			if t == "all" {
				allTargets = options
				break
			}
			return fmt.Errorf("%s is not a valid target", t)
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

	if max == 0 {
		// -1 means infinite length
		max = -1
	}
	if err = start(f, allTargets, min, max, r, saveResults, strict, aggressive, pretty); err != nil {
		return err
	}
	return nil
}

func start(f *os.File, targets []string, min, max int, regex *regexp.Regexp, save, strict, aggressive, pretty bool) error {
	fd := &FileConf{
		fd:             f,
		extractTargets: targets,
		minStrlen:      min,
		maxStrlen:      max,
		regexFilter:    regex,
		switches: struct {
			saveResults bool
			strict      bool
			pretty      bool
			aggressive  bool
		}{
			saveResults: save,
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

func (f *FileConf) initRegexp(targets map[string]string) error {
	ctargetexp := make(map[string]*regexp.Regexp)
	for s, regexPattern := range targetexp {
		var included = false
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
			regexPattern = fmt.Sprintf(regexPattern, strings.Join(extensions, "|"))
		}
		r, err := regexp.Compile(regexPattern)
		if err != nil {
			return fmt.Errorf("error compiling regex pattern: %v", err)
		}
		ctargetexp[s] = r
	}
	f.targetexp = ctargetexp
	return nil
}

func (f *FileConf) extract() error {
	categories := make(map[string][]string)
	reader := bufio.NewReader(f.fd)
	if err := f.initRegexp(targetexp); err != nil {
		return err
	}
	for {
		var strBytes []byte
		var fend, reading bool
		for {
			b, err := reader.ReadByte()
			if err != nil {
				if errors.Is(err, io.EOF) {
					fend = true
					break
				}
				return err
			}
			if b < asciiMin || b > asciiMax {
				if reading {
					reading = false
					break
				}
				continue
			}
			reading = true
			strBytes = append(strBytes, b)
		}
		if fend {
			break
		}
		if len(strBytes) < f.minStrlen || (len(strBytes) > f.maxStrlen && f.maxStrlen != -1) {
			continue
		}
		// filter out if matches with regex filter
		if f.regexFilter != nil {
			if validstr := f.regexFilter.MatchString(string(strBytes)); !validstr {
				continue
			}
		}
		if err := f.analyse(string(strBytes), &categories); err != nil {
			return err
		}
	}
	if f.switches.pretty {
		f.pretty(&categories)
	}
	if f.switches.saveResults {
		n, err := f.save(&categories)
		if err != nil {
			return fmt.Errorf("could not save %s: %v", n, err)
		}
		fmt.Printf("saved results as %s\n", n)
	}
	return nil
}

func (f *FileConf) pretty(categories *map[string][]string) {
	for category, data := range *categories {
		var maxlen int
		for _, d := range data {
			if len(d) > maxlen {
				maxlen = len(category + ": " + d)
			}
		}
		header := " " + strings.Repeat("=", maxlen+2) + " \n"
		title := "| " + category + strings.Repeat(" ", maxlen-len(category)) + " |\n"
		fmt.Printf(header + title)
		var length int
		var first = true
		for _, d := range data {
			d = category + ": " + d
			row := "| " + strings.ReplaceAll(d, "%", "%%") + strings.Repeat(" ", maxlen-len(d)) + " |\n"
			length = len(row) - 3
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
		matches := f.targetexp[t].FindAllString(str, -1)
		if len(matches) == 0 {
			continue
		}
		if !f.switches.strict {
			if !f.switches.saveResults {
				if !f.switches.pretty {
					fmt.Println(str)
				}
			}
		} else {
			for _, m := range matches {
				if len(m) < f.minStrlen || (len(m) > f.maxStrlen && f.maxStrlen != -1) {
					continue
				}
				if !f.switches.saveResults || !f.switches.pretty {
					if !f.switches.pretty {
						fmt.Println(m)
					}
				}
			}
		}
		if f.switches.saveResults || f.switches.pretty {
			for _, m := range matches {
				if len(m) < f.minStrlen || (len(m) > f.maxStrlen && f.maxStrlen != -1) {
					continue
				}
				if f.switches.strict {
					(*categories)[t] = append((*categories)[t], m)
				}
			}
			if !f.switches.strict {
				(*categories)[t] = append((*categories)[t], str)
			}
		}
		if !f.switches.aggressive {
			break
		}
	}
	return nil
}

func (f *FileConf) save(c *map[string][]string) (string, error) {
	saveFile := f.fd.Name() + ".spl.json"
	json, err := json.MarshalIndent(*c, "", "\t")
	if err != nil {
		return "", err
	}
	return saveFile, os.WriteFile(saveFile, json, 0600)
}