#!/bin/sh
CHECKSUM=`cat ${2} ${3} 2>/dev/null | md5sum 2>/dev/null | cut -d\  -f1 2>/dev/null`
echo "#define DB_CHECKSUM DB_VERSION_${CHECKSUM}" > ${1}
echo "#define DB_CHECKSUM_STR \"DB_VERSION_${CHECKSUM}\"" >> ${1}

