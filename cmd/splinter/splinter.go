package main

import (
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/pygrum/splinter/internal/splinter"
	log "github.com/sirupsen/logrus"
)

var (
	app         = kingpin.New("splinter", "cli tool for comprehensive analysis of file strings")
	file        = app.Arg("file", "name of file to analyze - (executable / image)").Required().String()
	targets     = app.Flag("targets", "string types to extract {url|ipv4|tag|registry|file|none|all} (comma-separated). 'none' extracts any printable characters (like 'strings')").Short('t').Default("all").String()
	ftargets    = app.Flag("filetypes", "specific filetypes to extract {general|script|exe|lib|macro|all}. exe - executables. macro - macro enabled office files. lib - shared libraries").Short('f').Default("all").String()
	maxLen      = app.Flag("max", "maximum extractable string length").Int()
	minLen      = app.Flag("min", "minimum extractable string length").Default("3").Int()
	saveResults = app.Flag("json", "save results as a json file").Bool()
	filter      = app.Flag("filter", "regex filter for all strings before extraction (like 'grep')").String()
	strict      = app.Flag("strict", "if target is found, only print the target and not the entire string it was found in").Short('s').Default("false").Bool()
	pretty      = app.Flag("pretty", "pretty print results (in category tables)").Default("false").Bool()
	agg         = app.Flag("agg", "attempt to find matches for every target in each string (aggressive mode)").Default("false").Bool()
)

func main() {
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))
	if err := splinter.Parse(*file, *targets, *ftargets, *filter, *minLen, *maxLen, *strict, *agg, *saveResults, *pretty); err != nil {
		log.Fatal(err)
	}
}
