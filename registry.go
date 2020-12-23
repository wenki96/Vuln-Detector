package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type WindowsInfo struct {
	SystemName string
	Version    string
	ReleaseID  string
}

type WinSoftware struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	//...
}

type Hotfix []string

// Get sub dir names
func getRegistrySubNames(dir string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, dir, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		//fmt.Println(err)
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Printf("Error read dir %s", dir)
	}
	return names
}

func getRegistryVaule(dir string, key string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, dir, registry.QUERY_VALUE)
	if err != nil {
		//fmt.Println(err)
	}
	defer k.Close()

	value, _, err := k.GetStringValue(key)
	if err != nil {
		//fmt.Println(err)
	}
	return value
}

func WindowsVersion() WindowsInfo {
	var version string
	name := getRegistryVaule(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName")
	kv := strings.Split(name, " ")
	if kv[1] == "Server" {
		if len(kv) >= 4 && kv[3][0] == 'R' {
			name = kv[0] + " " + kv[1] + " " + kv[2] + " " + kv[3]
		} else {
			name = kv[0] + " " + kv[1] + " " + kv[2]
		}
	} else {
		name = kv[0] + " " + kv[1]
	}
	if t := getRegistrySubNames(`Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`); len(t) == 0 {
		version = "32-bit"
	} else {
		version = "x64"
	}
	releaseID := getRegistryVaule(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ReleaseID")
	info := WindowsInfo{
		SystemName: name,
		Version:    version,
		ReleaseID:  releaseID,
	}
	return info
}

// Find KB...
func FindPatch() (map[string]bool, []string) {
	names := getRegistrySubNames(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`)

	h := Hotfix{}
	isExist := make(map[string]bool)

	for _, name := range names {
		m, err := regexp.MatchString("Package_\\d*\\w*for_\\w*KB(\\w+)~", name)
		if err != nil {
			fmt.Printf("Error Comparing to Regexp\n")
		}
		if m {
			i, j := strings.Index(name, "KB"), strings.Index(name, "~")
			if isExist[name[i:j]] {
				continue
			} else {
				isExist[name[i:j]] = true
				h = append(h, name[i:j])
			}
		} else {
			value := getRegistryVaule(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\`+name, "InstallLocation")
			i, j := strings.Index(value, "KB"), strings.Index(value, "-x")
			if i == -1 || j == -1 || isExist[value[i:j]] {
				continue
			} else {
				isExist[value[i:j]] = true
				h = append(h, value[i:j])
			}
		}
	}

	return isExist, h
}

func getNameAndVersion(softwareDir string, arch int, w *[]WinSoftware) {
	dirs := getRegistrySubNames(softwareDir)
	for _, dir := range dirs {
		n := getRegistryVaule(softwareDir+"\\"+dir, "DisplayName")
		v := getRegistryVaule(softwareDir+"\\"+dir, "DisplayVersion")
		var ar string
		if arch == 0 {
			ar = "32"
		} else {
			ar = "64"
		}
		if n != "" && v != "" {
			*w = append(*w, WinSoftware{
				Name:    n,
				Version: v,
				Arch:    ar,
			})
		}
	}
}

// Find name, version, arch of installed software
func FindSoftware() {
	softwareDir32 := `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	softwareDir64 := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

	w := []WinSoftware{}

	sysinfo := WindowsVersion()

	getNameAndVersion(softwareDir32, 0, &w)
	if sysinfo.Version == "64" {
		getNameAndVersion(softwareDir64, 1, &w)
	}
	data, _ := json.Marshal(w)
	fmt.Println(string(data))
}
