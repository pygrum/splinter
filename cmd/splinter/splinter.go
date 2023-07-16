package main

import (
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/pygrum/splinter/internal/splinter"
	log "github.com/sirupsen/logrus"
)

var (
	app         = kingpin.New("splinter", "cli tool for comprehensive analysis of file strings")
	file        = app.Arg("file", "name of file to analyse - (executable / image)").Required().String()
	targets     = app.Flag("targets", "string types to extract {url|ipv4|tag|file|registry|all} (comma-separated)").Short('t').Default("all").String()
	maxLen      = app.Flag("max", "maximum extractable string length").Int()
	minLen      = app.Flag("min", "minimum extractable string length").Default("3").Int()
	saveResults = app.Flag("json", "save results as a json file").Bool()
	filter      = app.Flag("filter", "regex filter for all strings before extraction (like 'grep -v')").String()
	strict      = app.Flag("strict", "if target is found, only print the target and not the entire string it was found in").Short('s').Default("false").Bool()
	pretty      = app.Flag("pretty", "pretty print results (in category tables)").Default("false").Bool()
	agg         = app.Flag("agg", "attempt to find matches for every target in each string (aggressive mode)").Default("false").Bool()
)

func main() {
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))
	if err := splinter.Parse(*file, *targets, *filter, *minLen, *maxLen, *strict, *agg, *saveResults, *pretty); err != nil {
		log.Fatal(err)
	}
}