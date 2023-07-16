.PHONY: build
build:
	go build cmd/splinter/splinter.go

.PHONY: win64
win64:
	GOOS=windows GOARCH=amd64 go build -o splinter_x64.exe cmd/splinter/splinter.go

.PHONY: win32
win32:
	GOOS=windows GOARCH=386 go build -o splinter_x86.exe cmd/splinter/splinter.go

