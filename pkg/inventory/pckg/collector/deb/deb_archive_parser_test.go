// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package deb

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"gitee.com/jd-opensource/sbom-tool/pkg/model"
	"gitee.com/jd-opensource/sbom-tool/pkg/util"
	"gitee.com/jd-opensource/sbom-tool/pkg/util/license"
)

func TestDEBArchiveParser_Parse(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []model.Package
		wantErr bool
	}{
		{
			"case-1",
			args{path: "test_material/deb/ukui-panel_4.0.0.0-ok0.10_amd64.deb"},
			[]model.Package{
				newPackage("dconf-gsettings-backend", "", ""),
				newPackage("gsettings-backend", "", ""),
				newPackage("libc6", "2.34", ""),
				newPackage("libdbusmenu-qt5-2", "0.5.1", ""),
				newPackage("libegl1", "", ""),
				newPackage("libgcc-s1", "3.0", ""),
				newPackage("libglib2.0-0", "2.36", ""),
				newPackage("libgsettings-qt1", "0.1+14.04.20140408", ""),
				newPackage("libkf5i18n5", "4.97.0", ""),
				newPackage("libkf5screen-bin", "4:5.17.5~", ""),
				newPackage("libkf5screen7", "4:5.6.2", ""),
				newPackage("libkf5waylandclient5", "4:5.74.0", ""),
				newPackage("libkf5windowsystem5", "5.35.0", ""),
				newPackage("libkysdk-qtwidgets", "", ""),
				newPackage("libkysdk-system", "", ""),
				newPackage("libkysdk-waylandhelper", "", ""),
				newPackage("libpipewire-0.3-0", "0.3.1", ""),
				newPackage("libqt5core5a", "5.15.1", ""),
				newPackage("libqt5dbus5", "5.14.1", ""),
				newPackage("libqt5gui5-gles", "5.14.1", ""),
				newPackage("libqt5gui5", "5.14.1", ""),
				newPackage("libqt5qml5", "5.0.2", ""),
				newPackage("libqt5quick5-gles", "5.14.1", ""),
				newPackage("libqt5quick5", "5.14.1", ""),
				newPackage("libqt5widgets5", "5.15.1", ""),
				newPackage("libqt5x11extras5", "5.6.0", ""),
				newPackage("libqt5xdg3", "3.1.0", ""),
				newPackage("libstdc++6", "5.2", ""),
				newPackage("libukui-log4qt1", "1.0.3", ""),
				newPackage("libx11-6", "", ""),
				newPackage("libxcb-composite0", "", ""),
				newPackage("libxcb-damage0", "", ""),
				newPackage("libxcb-image0", "0.2", ""),
				newPackage("libxcb-shape0", "", ""),
				newPackage("libxcb-util1", "0.4.0", ""),
				newPackage("libxcb1", "1.6", ""),
				newPackage("libxtst6", "", ""),
				newPackage("ukui-panel", "4.0.0.0-ok0.10", ""),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := DEBArchiveParser{}
			got, err := g.Parse(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Collect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !util.SliceEqual(got, tt.want, func(p1 model.Package, p2 model.Package) bool {
				return model.PackageEqual(&p1, &p2)
			}) {
				t.Errorf("Parse() got = %v, \nwant %v", got, tt.want)
			}
		})
	}
}

func TestLicensesFromCopyright(t *testing.T) {
	tests := []struct {
		path     string
		expected []string
	}{
		{
			path:     "test_material/license/copyright",
			expected: []string{"GPL-3.0-only", "GPL-3.0-or-later"},
		},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			f, err := os.Open(test.path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			actual := license.GetLicensesFromCopyright(f)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected package licenses (-want +got):\n%s", diff)
			}
		})
	}
}
