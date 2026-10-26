package main

import (
	dohfunctions "MyContainer/doh/c2functions"

	"github.com/MythicMeta/MythicContainer"
)

func main() {
	dohfunctions.Initialize()
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceC2,
	})
}
