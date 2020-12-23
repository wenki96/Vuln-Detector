package main

func main() {
	// fmt.Println(WindowsVersion())
	// FindPatch()
	// FindSoftware()

	// err := fetch(`https://feed.wazuh.com/vulnerability-detector/windows/msu-updates.json.gz`, `MSU.json.gz`)
	// if err != nil {
	// 	panic(err)
	// }

	searchVulns("./MSU.json.gz")
}
