package splinter

import (
	"math"
	"sync"
	"unicode"
)

var (
	generalExtensions = []string{
		"txt",
		"docx",
		"pdf",
		"jpg",
		"png",
		"gif",
		"csv",
		"doc",
		"xls",
		"xlsx",
		"ods",
		"odt",
		"ppt",
		"pptx",
		"css",
		"html",
	}
	scriptExtensions = []string{
		"py",
		"js",
		"php",
		"vbs",
		"swift",
		"sh",
	}
	libExtensions = []string{
		"dll",
		"so",
	}
	exeExtensions = []string{
		"apk",
		"exe",
		"com",
		"wsf",
		"bin",
		"bat",
		"run",
		"cmd",
		"inf",
		"ipa",
		"osx",
		"pif",
		"run",
		"wsh",
		"hta",
		"jar",
	}
	macroExtensions = []string{
		"docm",
		"dotm",
		"xlm",
		"xlsm",
		"xltm",
		"xlam",
		"xla",
		"ppam",
		"pptm",
		"potm",
		"ppsm",
		"sldm",
	}
)

// Expands the extensions array to create capitalised permutations
func Expand(exts []string, threads int) []string {
	var mu sync.Mutex
	var all_perms []string
	var wg sync.WaitGroup

	for i := 0; i < len(exts); i += threads {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			numGoroutines := threads
			if index+threads > len(exts) {
				numGoroutines = len(exts) - index
			}

			for j := 0; j < numGoroutines; j++ {
				perms := genPermutations(exts[index+j])
				mu.Lock()
				all_perms = append(all_perms, perms...)
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	return all_perms
}

func genPermutations(s string) []string {
	// 2^n because using lowercase and uppercase
	combos := make([]string, int(math.Pow(2, float64(len(s)))))
	for i, r := range s {
		var counter int
		var sw func(rune) rune
		var swint int
		localBase := int(math.Pow(2, float64(len(s)-(i+1))))
		for j := 0; j < len(combos); j++ {
			if counter%localBase == 0 {
				if swint == 1 {
					sw = unicode.ToLower
					swint = 0
				} else {
					sw = unicode.ToUpper
					swint = 1
				}
			}
			counter++
			combos[j] += string(sw(r))
		}
	}
	return combos
}
