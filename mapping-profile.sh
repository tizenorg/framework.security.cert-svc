#!/bin/sh

CERTSVC_PROFILE=$1

if [ "$1" = "wearable" ]
then
    echo "PROFILE = wearable"
    CERTSVC_PROFILE_COUNTERPART="mobile"
else
    echo "PROFILE = mobile"
    CERTSVC_PROFILE_COUNTERPART="wearable"
fi

mv vcore/src/vcore/Certificate_${CERTSVC_PROFILE}.h vcore/src/vcore/Certificate.h
mv vcore/src/vcore/OCSPImpl_${CERTSVC_PROFILE}.h vcore/src/vcore/OCSPImpl.h
rm vcore/src/vcore/Certificate_${CERTSVC_PROFILE_COUNTERPART}.h
rm vcore/src/vcore/OCSPImpl_${CERTSVC_PROFILE_COUNTERPART}.h
