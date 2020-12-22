package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/bitly/go-simplejson"
)

type Vul struct {
	Patch           string
	Product         string
	RestartRequired string
	Subtype         string
	Title           string
	URL             string
}

func fetch(url string, filepath string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	os.Remove(filepath)

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, response.Body)
	return err
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func unzip(gzipStream io.Reader) {
	unc, err := gzip.NewReader(gzipStream)
	if err != nil {
		log.Fatal("ExtractTarGz: NewReader failed")
	}

	js, err := simplejson.NewJson(StreamToByte(unc))

	if err != nil {
		fmt.Println("err:", err)
	}

	m, h := FindPatch()
	var r []string
	r = append(r, h...)

	for i := 0; i < 2; i++ {
		for k, _ := range js.Get("dependencies").MustMap() {
			for _, v := range js.Get("dependencies").Get(k).MustStringArray() {
				if m[v] && !m[k] {
					r = append(r, k)
					m[k] = true
				}
			}
		}
	}

	sort.Strings(r)

	mm := make(map[string]bool)
	result := []Vul{}

	for k, _ := range js.Get("vulnerabilities").MustMap() {
		for _, v := range js.Get("vulnerabilities").Get(k).MustArray() {
			if strings.Contains(v.(map[string]interface{})["product"].(string), "Windows 10") &&
				strings.Contains(v.(map[string]interface{})["product"].(string), "x64") &&
				strings.Contains(v.(map[string]interface{})["product"].(string), "2004") &&
				!m[v.(map[string]interface{})["patch"].(string)] {
				if !mm[k] {
					mm[k] = true
					result = append(result, Vul{
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

	fmt.Println(result)
}
