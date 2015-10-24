%define certsvc_feature_ocsp_crl     0
%define certsvc_feature_store_enable 1
%define certsvc_rw_datadir           /opt/share/cert-svc
%define certsvc_test_build           0

Name:    cert-svc
Summary: Certification service
Version: 1.0.2
Release: 1
Group:   System/Libraries
License: Apache-2.0
Source0: %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(xmlsec1)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(libxslt)
BuildRequires: pkgconfig(icu-i18n)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(key-manager)
BuildRequires: pkgconfig(secure-storage)
BuildRequires: ca-certificates
BuildRequires: boost-devel
%if 0%{?certsvc_feature_ocsp_crl}
BuildRequires: pkgconfig(vconf)
BuildRequires: pkgconfig(sqlite3)
%endif
Requires: tizen-security-policy
Requires: ca-certificates
Requires(post): openssl

%description
Certification service

%package devel
Summary:    Certification service (development files)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Certification service (developement files)

%if 0%{?certsvc_test_build}
%package test
Summary:  Certification service (tests)
Group:    System/Misc
Requires: boost-devel
Requires: %{name} = %{version}-%{release}

%description test
Certification service (tests)
%endif

%prep
%setup -q
cp -a %{SOURCE1001} .

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"

%ifarch %{ix86}
export CFLAGS="$CFLAGS -DTIZEN_EMULATOR_MODE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_EMULATOR_MODE"
export FFLAGS="$FFLAGS -DTIZEN_EMULATOR_MODE"
%endif

%{!?build_type:%define build_type "Release"}
cmake . -DPREFIX=%{_prefix} \
        -DEXEC_PREFIX=%{_exec_prefix} \
        -DLIBDIR=%{_libdir} \
        -DBINDIR=%{_bindir} \
        -DINCLUDEDIR=%{_includedir} \
%if 0%{?certsvc_feature_ocsp_crl}
        -DTIZEN_FEAT_CERTSVC_OCSP_CRL=1 \
%endif
%if 0%{?certsvc_feature_store_enable}
        -DTIZEN_FEAT_CERTSVC_STORE_CAPABILITY=1 \
%endif
%if 0%{?certsvc_test_build}
        -DCERTSVC_TEST_BUILD=1 \
%endif
        -DCMAKE_BUILD_TYPE=%{build_type} \
        -DSYSTEMD_UNIT_DIR=%{_unitdir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/%{name}

mkdir -p %{buildroot}%{certsvc_rw_datadir}/certs/user
mkdir -p %{buildroot}%{certsvc_rw_datadir}/certs/trusteduser
mkdir -p %{buildroot}%{certsvc_rw_datadir}/pkcs12
mkdir -p %{buildroot}%{certsvc_rw_datadir}/dbspace
mkdir -p %{buildroot}%{_datadir}/cert-svc/certs/code-signing/wac
mkdir -p %{buildroot}%{_datadir}/cert-svc/certs/code-signing/tizen
%if 0%{?certsvc_feature_ocsp_crl}
mkdir -p %{buildroot}%{_datadir}/cert-svc/certs/fota
%endif

%if 0%{?certsvc_feature_store_enable}
touch %{buildroot}%{certsvc_rw_datadir}/root-cert.sql
%endif

%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
ln -s ../cert-server.service %{buildroot}%{_unitdir}/multi-user.target.wants/
ln -s ../cert-server.socket %{buildroot}%{_unitdir}/sockets.target.wants/

ln -sf /opt/etc/ssl/certs %{buildroot}%{certsvc_rw_datadir}/certs/ssl
touch %{buildroot}%{certsvc_rw_datadir}/pkcs12/storage
chmod 766 %{buildroot}%{certsvc_rw_datadir}/pkcs12/storage

ln -sf /opt/share/ca-certificates/ca-certificate.crt %{buildroot}%{certsvc_rw_datadir}/

%clean
rm -rf %{buildroot}

%preun
if [ $1 == 0 ]; then
    systemctl stop cert-server.service
fi

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart cert-server.service
fi

echo "create .cert_svc_vcore.db"
%if 0%{?certsvc_feature_ocsp_crl}
if [ -z ${2} ]; then
    echo "This is new install of cert-svc"
    %{_bindir}/cert_svc_create_clean_db.sh
else
    echo "Find out old and new version of databases"
    VCORE_OLD_DB_VERSION=`sqlite3 /opt/dbspace/.cert_svc_vcore.db ".tables" | grep "DB_VERSION_"`
    VCORE_NEW_DB_VERSION=`cat %{_datadir}/cert-svc/cert_svc_vcore_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD vcore database version ${VCORE_OLD_DB_VERSION}"
    echo "NEW vcore database version ${VCORE_NEW_DB_VERSION}"

    if [ ${VCORE_OLD_DB_VERSION} -a ${VCORE_NEW_DB_VERSION} ]; then
        if [ ${VCORE_OLD_DB_VERSION} = ${VCORE_NEW_DB_VERSION} ]; then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
            %{_bindir}/cert_svc_create_clean_db.sh
        fi
    else
        echo "Calling /usr/bin/cert_svc_create_clean_db.sh"
        %{_bindir}/cert_svc_create_clean_db.sh
    fi
fi
rm %{_datadir}/cert-svc/cert_svc_vcore_db.sql
rm %{_bindir}/cert_svc_create_clean_db.sh
%endif

echo "add ssl table to certs-meta.db"
%if 0%{?certsvc_feature_store_enable}
rm -rf %{certsvc_rw_datadir}/dbspace/certs-meta.db
%{_bindir}/cert_svc_create_clean_store_db.sh %{_datadir}/cert-svc/cert_svc_store_db.sql
%{_bindir}/initialize_store_db.sh

cat %{certsvc_rw_datadir}/root-cert.sql | sqlite3 %{certsvc_rw_datadir}/dbspace/certs-meta.db
chown root:system %{certsvc_rw_datadir}/dbspace/certs-meta.db*
chmod 774 %{certsvc_rw_datadir}/dbspace/certs-meta.db*
chsmack -a cert-svc %{certsvc_rw_datadir}/dbspace/certs-meta.db*

rm %{_datadir}/cert-svc/cert_svc_store_db.sql
rm %{_bindir}/cert_svc_create_clean_store_db.sh
rm %{_bindir}/initialize_store_db.sh
rm %{certsvc_rw_datadir}/root-cert.sql
%endif

%postun
/sbin/ldconfig

%files
%defattr(-,root,root,-)
%manifest %{name}.manifest
%{_bindir}/cert-server
%{_unitdir}/cert-server.service
%{_unitdir}/cert-server.socket
%{_unitdir}/multi-user.target.wants/cert-server.service
%{_unitdir}/sockets.target.wants/cert-server.socket
%{_libdir}/libcert-svc.so.*
%{_libdir}/libcert-svc-vcore.so.*
%{_datadir}/license/%{name}
%{_datadir}/wrt-engine/schema.xsd
%dir %attr(0755,root,app) %{_datadir}/cert-svc
%dir %attr(0755,root,app) %{_datadir}/cert-svc/certs
%dir %attr(0755,root,app) %{_datadir}/cert-svc/certs/code-signing
%dir %attr(0755,root,app) %{_datadir}/cert-svc/certs/code-signing/wac
%dir %attr(0755,root,app) %{_datadir}/cert-svc/certs/code-signing/tizen
%dir %attr(0777,root,app) %{certsvc_rw_datadir}
%dir %attr(0777,root,app) %{certsvc_rw_datadir}/dbspace
%dir %attr(0777,root,app) %{certsvc_rw_datadir}/certs
%dir %attr(0777,root,app) %{certsvc_rw_datadir}/certs/user
%dir %attr(0777,root,app) %{certsvc_rw_datadir}/certs/trusteduser
%dir %attr(0777,root,app) %{certsvc_rw_datadir}/pkcs12
%{certsvc_rw_datadir}/ca-certificate.crt
%{certsvc_rw_datadir}/certs/ssl
%{certsvc_rw_datadir}/pkcs12/storage

%if 0%{?certsvc_feature_store_enable}
%{_datadir}/cert-svc/cert_svc_store_db.sql
%{_bindir}/cert_svc_create_clean_store_db.sh
%{_bindir}/initialize_store_db.sh
%{certsvc_rw_datadir}/root-cert.sql
%endif

%if 0%{?certsvc_feature_ocsp_crl}
%{_datadir}/cert-svc/cert_svc_vcore_db.sql
%{_bindir}/cert_svc_create_clean_db.sh
%endif

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/pkgconfig/*
%{_libdir}/libcert-svc.so
%{_libdir}/libcert-svc-vcore.so

%if 0%{?certsvc_test_build}
%files test
%defattr(-,root,root,-)
%{_bindir}/cert-svc-test*
/opt/apps/widget/tests/vcore_widget_uncompressed/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_hash/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_signature/*
/opt/apps/widget/tests/vcore_widget_uncompressed_negative_certificate/*
/opt/apps/widget/tests/vcore_widget_uncompressed_partner/*
/opt/apps/widget/tests/vcore_widget_uncompressed_partner_operator/*
/opt/apps/widget/tests/vcore_keys/*
/opt/apps/widget/tests/vcore_certs/*
/opt/apps/widget/tests/vcore_config/*
/opt/apps/widget/tests/pkcs12/*
/opt/apps/widget/tests/reference/*
/opt/etc/ssl/certs/8956b9bc.0
%{_datadir}/cert-svc/certs/code-signing/wac/root_cacert0.pem
%{certsvc_rw_datadir}/pkcs12/*
%{certsvc_rw_datadir}/cert-type/*
%{certsvc_rw_datadir}/tests/orig_c/data/caflag/*
%{certsvc_rw_datadir}/certs/root_ca*.der
%{certsvc_rw_datadir}/certs/second_ca*.der
%{certsvc_rw_datadir}/tests/*

/opt/apps/tpk/tests/verify-sig-tpk/*

%endif
