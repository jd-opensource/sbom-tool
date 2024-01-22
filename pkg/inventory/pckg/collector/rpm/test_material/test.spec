Summary: rpm project demo
Name: testapp
Version: 1.0.0
Release: 60%{?dist}
License: GPL-2.0-or-later
Source: http://www.ohse.de/uwe/releases/%{name}-%{version}.tar.gz
Patch1: testapp-1.0.0-glibc21.patch
Patch2: testapp-1.0.0.patch
Patch3: testapp-1.0.0.patch
Url: http://www.ohse.de/uwe/software/testapp.html
BuildRequires: gcc gettext
BuildRequires: make
BuildRequires: glibc = 2.2.2, git-devel
BuildRequires: clang >= 3.0.0, python3
