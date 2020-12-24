package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bitly/go-simplejson"
)

type Vul struct {
	CVE             string `json:"CVE"`
	Patch           string `json:"patch"`
	Product         string `json:"product"`
	RestartRequired string `json:"restart_required"`
	Subtype         string `json:"subtype"`
	Title           string `json:"title"`
	URL             string `json:"url"`
}

func fetch(url string, filepath string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if _, err := os.Stat(filepath); err == nil {
		os.Remove(filepath)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, response.Body)
	return err
}

func streamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func unzip(gzipStream io.Reader) *simplejson.Json {
	unc, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Fatal("ExtractTarGz: NewReader failed")
	}

	js, err := simplejson.NewJson(streamToByte(unc))

	if err != nil {
		fmt.Println("err:", err)
	}

	return js
}

func searchVulns(file string) {
	r, err := os.Open(file)
	if err != nil {
		fmt.Println("error")
	}
	js := unzip(r)

	m, h := FindPatch()
	var kbs []string
	kbs = append(kbs, h...)

	for i := 0; i < 2; i++ {
		for k, _ := range js.Get("dependencies").MustMap() {
			for _, v := range js.Get("dependencies").Get(k).MustStringArray() {
				if m[v] && !m[k] {
					kbs = append(kbs, k)
					m[k] = true
				}
			}
		}
	}

	mm := make(map[string]bool)

	result := []Vul{}

	sysinfo := WindowsVersion()

	fmt.Println(sysinfo)

	iswin10 := sysinfo.SystemName == "Windows 10"

	sp := findServicePack()

	for k, _ := range js.Get("vulnerabilities").MustMap() {
		for _, v := range js.Get("vulnerabilities").Get(k).MustArray() {
			product := v.(map[string]interface{})["product"].(string)
			if strings.Contains(product, sysinfo.SystemName) && strings.Contains(product, sysinfo.Version) && !m[v.(map[string]interface{})["patch"].(string)] {
				p := true
				if iswin10 { //win10
					p = (strings.Contains(product, "10 Version") || strings.Contains(product, "10 version")) && strings.Contains(product, sysinfo.ReleaseID)
				}
				if !mm[k] && p {
					//framework
					if strings.Contains(product, ".NET Framework") && !strings.Contains(product, findDotNetFramwork()) {
						continue
					}
					//service pack
					// sp == "0" && strings.Contains(product, "Service Pack") ||
					if sp != "0" && !strings.Contains(product, "Service Pack "+sp) {
						continue
					}
					mm[k] = true
					result = append(result, Vul{
						CVE:             k,
						Patch:           v.(map[string]interface{})["patch"].(string),
						Product:         v.(map[string]interface{})["product"].(string),
						RestartRequired: v.(map[string]interface{})["restart_required"].(string),
						Subtype:         v.(map[string]interface{})["subtype"].(string),
						Title:           v.(map[string]interface{})["title"].(string),
						URL:             v.(map[string]interface{})["url"].(string),
					})
					continue
				}
			}
		}
	}

	f, err := os.Create("output.json")
	if err != nil {
		fmt.Println("Create file failed", err.Error())
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Println("Encoder failed", err.Error())

	}

	f.Write(data)
}
