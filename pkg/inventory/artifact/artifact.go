// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package artifact

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/anchore/packageurl-go"
	"golang.org/x/exp/slices"

	"gitee.com/jd-opensource/sbom-tool/pkg/config"
	"gitee.com/jd-opensource/sbom-tool/pkg/inventory/env"
	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/license"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/log"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/ziputil"
)

// artifactExts is the supported artifact extensions
var archiveExts = []string{".zip", ".war", ".jar"}

func ArtifactPackage(cfg *config.ArtifactConfig) *model.Package {
	return &model.Package{
		Name:     cfg.PackageName,
		Version:  cfg.PackageVersion,
		Supplier: cfg.PackageSupplier,
		PURL:     artifactPURL(model.PkgTypeGeneric, "", cfg.PackageName, cfg.PackageVersion),
	}
}

// Collect collects the artifact information
func Collect(cfg *config.ArtifactConfig, projectPath string) (*model.Artifact, error) {
	distPath := cfg.DistPath
	stat, err := os.Stat(distPath)
	pkg := ArtifactPackage(cfg)
	if err != nil {
		log.Warnf("dist path is invalid")
		return &model.Artifact{Package: *pkg}, nil
	}
	if !stat.IsDir() {
		if strings.HasSuffix(distPath, ".rpm") {
			return collectRPM(cfg)
		} else if strings.HasSuffix(distPath, ".deb") {
			return collectDEB(cfg)
		}
	}

	files := make([]model.File, 0)
	mainPkglicenses := make([]string, 0)
	if projectPath != "" {
		mainPkglicenses, _, _ = license.ParseLicenseFromDir(projectPath)
	}

	var id string
	if stat.IsDir() {
		files, err = collectDirectory(cfg)
		if err != nil {
			return nil, err
		}
		pkg.FilesAnalyzed = true

		if len(mainPkglicenses) == 0 {
			mainPkglicenses, _, _ = license.ParseLicenseFromDir(cfg.DistPath)
		}
	} else if cfg.ExtractFiles && util.SliceAny(archiveExts, func(s string) bool { return strings.HasSuffix(cfg.DistPath, s) }) {
		files, err = collectArchive(cfg)
		if err != nil {
			return nil, err
		}
		pkg.FilesAnalyzed = true
		id, _ = util.SHA1SumFile(cfg.DistPath)

		if len(mainPkglicenses) == 0 {
			mainPkglicenses = license.GetLicenseByZipFile(cfg.DistPath)
		}
	} else {
		sha1, _ := util.SHA1SumFile(distPath)
		pkg.FilesAnalyzed = false
		pkg.VerificationCode = sha1
		id = pkg.VerificationCode
	}

	if len(mainPkglicenses) > 0 {
		mainPkglicenses = license.UniqueStrings(mainPkglicenses)
	}
	pkg.LicenseDeclared = mainPkglicenses

	if pkg.FilesAnalyzed && len(files) > 0 {
		// sort files by name
		slices.SortFunc(files, func(a, b model.File) bool {
			return strings.Compare(a.Name, b.Name) < 0
		})
		// calculate verification code
		pkg.VerificationCode = util.VerifyCode(files, func(file model.File) string {
			index := util.SliceFirst(file.Checksums, func(sum model.FileChecksum) bool {
				return sum.Algorithm == "SHA1"
			})
			if index > -1 && index < len(file.Checksums) {
				return file.Name + " " + file.Checksums[index].Value
			}
			return file.Name
		})
		if len(id) == 0 {
			id = pkg.VerificationCode
		}
	}
	envInfo := env.GetEnvInfo()
	return &model.Artifact{
		ID:      id,
		Package: *pkg,
		Build: model.Build{
			OS:       envInfo.OS,
			Arch:     envInfo.Arch,
			Kernel:   envInfo.Kernel,
			Builder:  envInfo.Builder,
			Compiler: envInfo.Compiler,
		},
		Files: files,
	}, nil
}

// collectDirectory collects the files in the directory
func collectDirectory(cfg *config.ArtifactConfig) ([]model.File, error) {
	doneChan := make(chan struct{})
	pathsChan, errorChan := util.WalkFilesWithMatcher(cfg.DistPath, doneChan, cfg.IgnoreDirsSet(), nil)
	resultChan := make(chan *model.File)
	parallelism := cfg.Parallelism
	var wg sync.WaitGroup
	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go func() {
			defer wg.Done()
			for path := range pathsChan {
				md5, _ := util.MD5SumFile(path)
				sha1, _ := util.SHA1SumFile(path)
				sha256, _ := util.SHA256SumFile(path)
				sm3, _ := util.SM3SumFile(path)
				file := model.File{
					Name: strings.TrimPrefix(path, cfg.DistPath),
					Checksums: []model.FileChecksum{
						{Algorithm: "MD5", Value: md5},
						{Algorithm: "SHA1", Value: sha1},
						{Algorithm: "SHA256", Value: sha256},
						{Algorithm: "SM3", Value: sm3},
					},
				}
				resultChan <- &file
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	files := make([]model.File, 0)
	for f := range resultChan {
		files = append(files, *f)
	}
	if err := <-errorChan; err != nil {
		return nil, err
	}
	return files, nil
}

// collectArchive collects the files in the archive
func collectArchive(cfg *config.ArtifactConfig) ([]model.File, error) {
	resultChan := make(chan *model.File)
	errorChan := make(chan error)
	go func() {
		err := ziputil.TraverseFilesInZip(cfg.DistPath, func(zipFile *zip.File) error {
			if zipFile.FileInfo().IsDir() {
				return nil
			}
			md5, err := func() (string, error) {
				reader, err := zipFile.Open()
				if err != nil {
					return "", fmt.Errorf("open zip file error: %w", err)
				}
				defer func(reader io.ReadCloser) {
					_ = reader.Close()
				}(reader)
				return util.MD5Sum(reader)
			}()
			if err != nil {
				return err
			}
			sha1, err := func() (string, error) {
				reader, err := zipFile.Open()
				if err != nil {
					return "", fmt.Errorf("open zip file error: %w", err)
				}
				defer func(reader io.ReadCloser) {
					_ = reader.Close()
				}(reader)
				return util.SHA1Sum(reader)
			}()
			if err != nil {
				return err
			}
			sha256, err := func() (string, error) {
				reader, err := zipFile.Open()
				if err != nil {
					return "", fmt.Errorf("open zip file error: %w", err)
				}
				defer func(reader io.ReadCloser) {
					_ = reader.Close()
				}(reader)
				return util.SHA256Sum(reader)
			}()
			if err != nil {
				return err
			}
			sm3, err := func() (string, error) {
				reader, err := zipFile.Open()
				if err != nil {
					return "", err
				}
				defer func(reader io.ReadCloser) {
					_ = reader.Close()
				}(reader)
				return util.SM3Sum(reader)
			}()
			if err != nil {
				return err
			}
			file := model.File{
				Name: zipFile.Name,
				Checksums: []model.FileChecksum{
					{Algorithm: "MD5", Value: md5},
					{Algorithm: "SHA1", Value: sha1},
					{Algorithm: "SHA256", Value: sha256},
					{Algorithm: "SM3", Value: sm3},
				},
			}
			resultChan <- &file
			return nil
		})
		close(resultChan)
		errorChan <- err
	}()

	files := make([]model.File, 0)
	for f := range resultChan {
		files = append(files, *f)
	}
	if err := <-errorChan; err != nil {
		return nil, err
	}

	return files, nil
}

func artifactPURL(pkgType, namespace, name, version string) string {
	return packageurl.NewPackageURL(pkgType, namespace, name, version, nil, "").ToString()
}
