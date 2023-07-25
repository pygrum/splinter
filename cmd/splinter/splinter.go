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
	targets     = app.Flag("targets", "string types to extract {[u]rl ipv[4] [r]egistry [p]ath [f]ile [e]mail [w]allet [n]one [a]ll} (comma-separated). 'none' extracts any printable characters (like 'strings')").Short('t').Default("all").String()
	ftargets    = app.Flag("filetypes", "specific filetypes to extract {[c]ommon [s]cript [e]xe [l]ib [m]acro [a]ll}. exe - executables. macro - macro enabled office files. lib - shared libraries").Short('f').Default("all").String()
	maxLen      = app.Flag("max", "maximum extractable string length").Int()
	minLen      = app.Flag("min", "minimum extractable string length").Default("4").Int()
	jsonResults = app.Flag("json", "print results in json format").Short('j').Bool()
	filter      = app.Flag("filter", "regex filter for all strings before extraction (like 'grep')").String()
	strict      = app.Flag("nostrict", "if target is found, print the entire string that it was found in").Short('s').Default("false").Bool()
	encoding    = app.Flag("encoding", "file encoding format (UTF8=s, UTF16LE=l, UTF16BE=b)").Default("s").Short('e').String()
	pretty      = app.Flag("pretty", "pretty print results (in category tables)").Default("false").Short('p').Bool()
	agg         = app.Flag("agg", "attempt to find matches for every target in each string (aggressive mode)").Default("false").Bool()
)

func main() {
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))
	if err := splinter.Parse(*file, *targets, *ftargets, *filter, *minLen, *maxLen, *encoding, *strict, *agg, *jsonResults, *pretty); err != nil {
		log.Fatal(err)
	}
}
