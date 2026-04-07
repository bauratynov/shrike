Name:       shrike
Version:    0.28.0
Release:    1%{?dist}
Summary:    x86-64 / AArch64 ROP gadget finder
License:    MIT
URL:        https://github.com/bauratynov/shrike
Source0:    %{name}-%{version}.tar.gz
BuildRequires: gcc, make

%description
Minimal, dependency-free gadget scanner for ELF64 binaries.
Emits text, JSON, SARIF, pwntools-compatible Python, and more.

%prep
%autosetup

%build
make %{?_smp_mflags} CFLAGS="%{optflags} -std=c99 -D_GNU_SOURCE -Iinclude"

%install
install -Dm0755 shrike %{buildroot}%{_bindir}/shrike

%files
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/shrike

%changelog
* Fri Apr 18 2026 Baurzhan Atynov <bauratynov@gmail.com> - 0.28.0-1
- Initial packaging release.
