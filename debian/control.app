Source: mgr-app
Section: libs
Priority: extra
Maintainer: SangJun Na <juni.na@samsung.com>, Manhyun Hwang <mh222.hwang@samsung.com>, Eunmi Son <eunmi.son@samsung.com>
Build-Depends: debhelper (>= 5),
 libappcore-efl-dev,
 autotools-dev,
 libelm-dev,
 libslp-setting-dev,
 libui-gadget-dev,
 libbundle-dev,
 libaul-1-dev,
 libefreet-dev,
 libeina-dev,
 shared-mime-info,
# java-runtime-dev,
 libail-0-dev,
 libpkgmgr-client-dev,
 libjava-parser-dev

Package: mgr-app-0
Section: libs
Architecture: armel
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: Manage Application package

Package: mgr-app-dbg
Section: debug
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, mgr-app-0 (= ${binary:Version})
Description: Manage Application debug(unstripped) package
