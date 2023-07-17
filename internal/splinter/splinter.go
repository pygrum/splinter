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
	asciiMin      = 0x20
	asciiMax      = 0x7e
	expandThreads = 3
)

var (
	taroptions  = []string{"url", "ipv4", "tag", "file", "registry"}
	extoptions  = []string{"general", "script", "exe", "lib", "macro"}
	fileoptions = map[string][]string{
		"general": generalExtensions,
		"script":  scriptExtensions,
		"exe":     exeExtensions,
		"lib":     libExtensions,
		"macro":   macroExtensions,
	}
	targetexp = map[string]string{
		"url":      `\bhttps?:\/\/[^"` + "`" + `\s]+`,
		"ipv4":     `(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3})`,
		"tag":      `(<.*>.*<.*/?>|</?.*>)`,
		"file":     `.+?\.(?i)(?:%s)`,
		"registry": `(?i)(HKLM:|hkey_local_machine)\\(?:[^\\\s]+\\)*[^\\\s]+`,
		"all":      `.*`,
	}
)

type FileConf struct {
	fd                   *os.File
	extractTargets       []string
	fileTargets          []string
	minStrlen, maxStrlen int
	targetexp            map[string]*regexp.Regexp
	regexFilter          *regexp.Regexp
	switches             struct {
		saveResults, strict, pretty, aggressive bool
	}
}

func validTargets(targets, options []string) (string, bool) {
	for _, t := range targets {
		var valid bool
		for _, o := range options {
			if t == o {
				valid = true
				break
			}
		}
		if !valid {
			return t, false
		}
	}
	return "", true
}

func Parse(file, targets, ftargets, filter string, min, max int, strict, aggressive, saveResults, pretty bool) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}

	allTargets := strings.Split(targets, ",")
	fileTargets := strings.Split(ftargets, ",")

	tg, valid := validTargets(allTargets, taroptions)

	if !valid {
		if tg == "all" {
			allTargets = taroptions
		} else if tg == "none" {
			allTargets = []string{"all"}
		} else {
			return fmt.Errorf("%s is not a valid target", tg)
		}
	}

	tg, valid = validTargets(fileTargets, extoptions)

	if !valid {
		if tg == "all" {
			fileTargets = extoptions
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

	if max == 0 {
		// -1 means infinite length
		max = -1
	}
	if err = start(f, allTargets, fileTargets, min, max, r, saveResults, strict, aggressive, pretty); err != nil {
		return err
	}
	return nil
}

func start(f *os.File, targets, fileTargets []string, min, max int, regex *regexp.Regexp, save, strict, aggressive, pretty bool) error {
	fd := &FileConf{
		fd:             f,
		extractTargets: targets,
		fileTargets:    fileTargets,
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
		// if
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
		fmt.Printf("saved results to %s\n", n)
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
		matches := f.targetexp[t].FindAllString(str, -1)
		if len(matches) == 0 {
			continue
		}
		if !f.switches.strict {
			if !f.switches.saveResults && !f.switches.pretty {
				fmt.Println(str)
			}
		} else {
			for _, m := range matches {
				if len(m) < f.minStrlen || (len(m) > f.maxStrlen && f.maxStrlen != -1) {
					continue
				}
				if !f.switches.saveResults && !f.switches.pretty {
					fmt.Println(m)
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
	fmt.Println(string(json))
	return saveFile, os.WriteFile(saveFile, json, 0600)
}
