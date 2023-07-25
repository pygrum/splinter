package splinter

var (
	commonExtensions = []string{
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
		"rar",
		"zip",
		"tmp",
	}
	scriptExtensions = []string{
		"py",
		"js",
		"php",
		"vbs",
		"swift",
		"sh",
		"ps1",
	}
	libExtensions = []string{
		"dll",
		`so(\.+[0-9])?`,
		"dylib",
	}
	exeExtensions = []string{
		"apk",
		"exe",
		"wsf",
		"bin",
		"bat",
		"run",
		"cmd",
		"osx",
		"wsh",
		"hta",
		"jar",
		"bundle",
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
