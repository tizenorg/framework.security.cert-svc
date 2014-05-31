#sbs-git:slp/pkgs/c/cert-svc cert-svc 1.0.1 ad7eb7efcefb37b06017c69cb2fc44e6f7b6cab7
Name:    cert-svc
Summary: Certification service
Version: 1.0.1
Release: 45
Group:   System/Libraries
License: SAMSUNG
Source0: %{name}-%{version}.tar.gz
Source1: %{name}.manifest

Requires(post):   /sbin/ldconfig
Requires(postun): /sbin/ldconfig

BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(evas)
BuildRequires: pkgconfig(dpl-efl)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(libpcre)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libxslt)

Provides: libcert-svc-vcore.so.1

%description
Certification service


%package devel
Summary:    Certification service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service (developement files)

%prep
%setup -q

%build
%{!?build_type:%define build_type "Release"}
cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DBINDIR=%{_bindir} \
        -DINCLUDEDIR=%{_includedir} \
        -DCMAKE_BUILD_TYPE=%{build_type}
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/%{name}
%make_install
install -D %{SOURCE1} %{buildroot}%{_datadir}/%{name}.manifest
ln -sf /opt/etc/ssl/certs %{buildroot}/opt/share/cert-svc/certs/ssl
touch %{buildroot}/opt/share/cert-svc/pkcs12/storage
chmod 766 %{buildroot}/opt/share/cert-svc/pkcs12/storage

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
if [ -z ${2} ]; then
    echo "This is new install of wrt-security"
    echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
    /usr/bin/cert_svc_create_clean_db.sh
else
    # Find out old and new version of databases
    VCORE_OLD_DB_VERSION=`sqlite3 /opt/dbspace/.cert_svc_vcore.db ".tables" | grep "DB_VERSION_"`
    VCORE_NEW_DB_VERSION=`cat /usr/share/cert-svc/cert_svc_vcore_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD vcore database version ${VCORE_OLD_DB_VERSION}"
    echo "NEW vcore database version ${VCORE_NEW_DB_VERSION}"

    if [ ${VCORE_OLD_DB_VERSION} -a ${VCORE_NEW_DB_VERSION} ]; then
        if [ ${VCORE_OLD_DB_VERSION} = ${VCORE_NEW_DB_VERSION} ]; then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
            /usr/bin/cert_svc_create_clean_db.sh
        fi
    else
        echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
        /usr/bin/cert_svc_create_clean_db.sh
    fi
fi

%postun
/sbin/ldconfig

%files
%defattr(-,root,root,-)
%manifest %{_datadir}/%{name}.manifest
%attr(0755,root,root) %{_bindir}/cert_svc_create_clean_db.sh
%{_libdir}/*.so.*
#%{_bindir}/dpkg-pki-sig
/opt/share/cert-svc/targetinfo
%{_datadir}/cert-svc/cert_svc_vcore_db.sql
%{_datadir}/license/%{name}
%dir %attr(0755,root,use_cert) /usr/share/cert-svc
%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs
%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing
%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing/native
%dir %attr(0755,root,use_cert) /usr/share/cert-svc/ca-certs/code-signing/wac
%dir %attr(0775,root,use_cert) /opt/share/cert-svc
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing/wac
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/code-signing/tizen
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim/operator
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/sim/thirdparty
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/certs/user
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/certs/trusteduser
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm/security
%dir %attr(0775,root,use_cert) /opt/share/cert-svc/certs/mdm/security/cert
%dir %attr(0777,root,use_cert) /opt/share/cert-svc/pkcs12
/opt/share/cert-svc/certs/ssl
/opt/share/cert-svc/pkcs12/storage

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/*.so
