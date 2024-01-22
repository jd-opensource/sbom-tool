// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package license

import (
	"bufio"
	"fmt"
	"io"
	"os"
	paths "path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/go-enry/go-license-detector/v4/licensedb"

	"gitee.com/JD-opensource/sbom-tool/pkg/util"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/log"
	"gitee.com/JD-opensource/sbom-tool/pkg/util/ziputil"
)

var (
	regRmHttp                 = regexp.MustCompile(`^(https?://)`)
	regPunctuation            = regexp.MustCompile(`[-‒–—―⁓⸺⸻~˗‐‑⁃⁻₋_−∼⎯⏤─➖𐆑֊﹘﹣－]+`)
	regRmFileSuffix           = regexp.MustCompile(`\.(txt|php|html)$`)
	CDDL1AndGPL1              = "cddl+gpl_1_1"
	NONE_LICENSE              = "NONE"
	NOASSERTION_LICENSE       = "NOASSERTION"
	ConfidenceMinimumValue    = float32(0.9)
	licenseFileNameRe         = regexp.MustCompile("li[cs]en[cs]e(s?)")
	CopyrightFileName         = "copyright"
	copyrightPattern          = regexp.MustCompile(`^License: (?P<license>\S*)`)
	copyrightPathPattern      = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
	deprecated_license_prefix = "deprecated_"
)

var licFileNames = []string{
	"li[cs]en[cs]e(s?)",
	"copy(left|right|ing)",
	"bsd",
	"mit",
	"apache",
	"legal",
	"l?gpl([-_ v]?)(\\d\\.?\\d)?",
}

var licFileRe = regexp.MustCompile(
	fmt.Sprintf("^(|.*[-_. ])(%s)(|[-_. ].*)$",
		strings.Join(licFileNames, "|")))

type LicenseGuess struct {
	Name       string
	Confidence float32
}

// ParseLicenseURL parses the license url and returns the license ID.
// licenseLowercaseKeys is a map of lowercase license names to license IDs.
func ParseLicenseURL(key string) (value, other string, exists bool) {
	if strings.Contains(strings.ToLower(key), "apache") && strings.Contains(key, "2") {
		return licenseLowercaseKeys["apache 2"], "", true
	}

	if strings.Contains(strings.ToLower(key), CDDL1AndGPL1) {
		value := fmt.Sprintf("%s;%s", licenseLowercaseKeys["cddl-1.1"], licenseLowercaseKeys["gpl-1+"])
		return value, "", true
	}

	key = strings.TrimSpace(key)
	key = regRmHttp.ReplaceAllString(key, "")
	key = regPunctuation.ReplaceAllString(key, "-")
	key = strings.TrimRight(key, "/")
	key = regRmFileSuffix.ReplaceAllString(key, "")
	arr := strings.Split(key, "/")
	key = arr[len(arr)-1]

	key = strings.ReplaceAll(key, "standalone", "")
	key = strings.ReplaceAll(key, "license", "")
	key = strings.ReplaceAll(key, "ce", "")
	key = strings.TrimRight(key, "+")
	key = strings.TrimRight(key, "-")
	key = strings.TrimSpace(key)

	if key == "" {
		return "", "", false
	}

	if value, exists := licenseLowercaseKeys[strings.ToLower(key)]; exists {
		return value, "", exists
	}

	return "", "", true
}

// ParseLicenseName parses the license name and returns the license ID.
func ParseLicenseName(key string) (value, other string, exists bool) {
	key = strings.TrimSpace(key)

	if strings.Contains(strings.ToLower(key), "apache") && strings.Contains(key, "2") {
		return licenseLowercaseKeys["apache 2"], "", true
	}

	if strings.Contains(strings.ToLower(key), CDDL1AndGPL1) {
		value := fmt.Sprintf("%s;%s", licenseLowercaseKeys["cddl-1.1"], licenseLowercaseKeys["gpl-1+"])
		return value, "", true
	}

	if key == "" {
		return "", "", false
	}

	if value, exists := licenseLowercaseKeys[strings.ToLower(key)]; exists {
		return value, "", exists
	}

	if value, exists := licenseNameKeys[key]; exists {
		return value, "", exists
	}

	return "", "", true
}

// ParseLicenseFromDir parses the license from the directory and returns the license ID.
func ParseLicenseFromDir(path string) (value []string, other string, exists bool) {
	licenseList := make([]string, 0)
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("主包license扫描无法打开文件 %q: %v\n", p, err)
		}
		if !info.IsDir() && info.Name() == CopyrightFileName {
			copyrightFileContext, err := os.Open(p)
			if err != nil {
				log.Errorf("主包license扫描无法读取文件 %q: %v\n", p, err)
			}
			licenseList = GetLicensesFromCopyright(copyrightFileContext)
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		log.Errorf("主包license扫描路径失败 %q: %v\n", path, err)
	}

	if len(licenseList) > 0 {
		return licenseList, "", true
	}

	res := licensedb.Analyse(path)

	if len(res) == 0 {
		return licenseList, "", false
	}

	immutableT := reflect.TypeOf(res[0])
	if _, ok := immutableT.FieldByName("error"); ok {
		return licenseList, "", false
	}

	if len(res[0].Matches) == 0 {
		return licenseList, "", false
	}

	if !licenseFileNameRe.MatchString(strings.ToLower(res[0].Matches[0].File)) {
		return licenseList, "", false
	}

	if res[0].Matches[0].Confidence < ConfidenceMinimumValue {
		return licenseList, "", false
	}

	licenseName := res[0].Matches[0].License
	if strings.Contains(licenseName, deprecated_license_prefix) {
		name, _, _ := ParseLicenseName(strings.TrimPrefix(licenseName, deprecated_license_prefix))
		if len(strings.TrimSpace(name)) != 0 {
			licenseList = append(licenseList, name)
		}
	} else {
		licenseList = append(licenseList, licenseName)
	}
	return licenseList, "", true
}

// ParseLicenseFromContent parses the license content and returns the license ID.
func ParseLicenseFromContent(content string) (value, other string, exists bool) {
	textMap := licensedb.InvestigateLicenseText([]byte(content))
	licenseGuessList := make([]LicenseGuess, 0)
	if len(textMap) == 0 {
		return "", "", false
	}

	for key, val := range textMap {
		if val < ConfidenceMinimumValue {
			continue
		}
		if strings.Contains(key, deprecated_license_prefix) {
			continue
		}

		licenseGuessList = append(licenseGuessList, LicenseGuess{Name: key, Confidence: val})
	}

	if len(licenseGuessList) == 0 {
		return "", "", false
	}

	sort.Slice(licenseGuessList, func(i, j int) bool {
		return licenseGuessList[i].Confidence > licenseGuessList[j].Confidence
	})

	return licenseGuessList[0].Name, "", true
}

// SplitLicense splits the license string and returns the license ID.
func SplitLicense(key string, licenseList []string) []string {
	arr := strings.Split(key, ";")
	licenseList = append(licenseList, arr...)
	return licenseList
}

// UniqueStrings returns the unique strings.
func UniqueStrings(strs []string) []string {
	m := make(map[string]bool)
	var result []string
	for _, s := range strs {
		if s == "" {
			continue
		}
		if _, ok := m[s]; !ok {
			m[s] = true
			result = append(result, s)
		}
	}
	return result
}

func GetLicenseByZipFile(filePath string) []string {
	results := make([]string, 0)
	contextMap := make(map[string]string)
	zipReader, err := ziputil.OpenZip(filePath)
	if err != nil {
		log.Errorf("unable to OpenZip %s. error:%s\n", filePath, err.Error())
		return results
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip %s. error:%s\n", filePath, err.Error())
		}
	}()

	for _, file := range zipReader.Reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if licFileRe.MatchString(strings.ToLower(paths.Base(file.Name))) && strings.Count(file.Name, "/") < 2 {
			contextMap[file.Name] = ziputil.ReadFileContext(file)
		}
	}

	for _, context := range contextMap {
		value, _, _ := ParseLicenseFromContent(context)
		results = append(results, value)
	}

	return UniqueStrings(results)
}

func CreateLicenseExpression(licenses []string) string {
	filteredLicenses := make([]string, 0)
	for _, license := range licenses {
		if len(strings.TrimSpace(license)) != 0 {
			filteredLicenses = append(filteredLicenses, license)
		}
	}
	licenseExpression := strings.Join(filteredLicenses, " AND ")
	licenseExpression = strings.TrimPrefix(licenseExpression, " AND ")
	licenseExpression = strings.TrimSuffix(licenseExpression, " AND ")
	return licenseExpression
}

func EnsureSingleLicense(name string) string {
	licenseName := strings.TrimSpace(name)
	if strings.Contains(licenseName, " or ") || strings.Contains(licenseName, " and ") {
		return ""
	}
	if licenseName != "" && strings.ToLower(licenseName) != "none" {
		licenseName = strings.TrimSuffix(licenseName, ".")
		licenseName, _, _ = ParseLicenseName(licenseName)
	}
	return licenseName
}

func GetLicensesFromCopyright(reader io.Reader) []string {
	licenseList := make([]string, 0)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if value := findLicenseShortName(copyrightPattern, line); value != "" {
			licenseList = append(licenseList, value)
		}
		if value := findLicenseShortName(copyrightPathPattern, line); value != "" {
			licenseList = append(licenseList, value)
		}
	}

	if len(licenseList) > 0 {
		licenseList = util.SliceUnique(licenseList)
		sort.Strings(licenseList)
	}

	return licenseList
}

func findLicenseShortName(pattern *regexp.Regexp, line string) string {
	licenseShortName := ""
	matches := pattern.FindStringSubmatch(line)
	if matches != nil && len(matches) == 2 {
		licenseShortName = matches[1]
	}

	if licenseShortName != "" {
		licenseShortName = EnsureSingleLicense(licenseShortName)
	}
	return licenseShortName
}
