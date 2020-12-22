package main

import (
	"fmt"
	"os"
)

func main() {
	// fmt.Println(WindowsVersion())
	// FindPatch()
	// FindSoftware()

	// err := fetch(`https://feed.wazuh.com/vulnerability-detector/windows/msu-updates.json.gz`, `MSU.json.gz`)
	// if err != nil {
	// 	panic(err)
	// }

	r, err := os.Open("./MSU.json.gz")
	if err != nil {
		fmt.Println("error")
	}
	unzip(r)
}
