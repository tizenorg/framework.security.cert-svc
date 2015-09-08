/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*!
 * @author      Piotr Marcinkiewicz(p.marcinkiew@samsung.com)
 * @version     0.4
 * @file        CommonCertValidator.cpp
 * @brief       Common routines for certificate validation over OCSP and CRL
 */

#include "RevocationCheckerBase.h"

#include <cstdlib>

#include <openssl/pem.h>

#include <dpl/scoped_fclose.h>

#include "Certificate.h"
#include "CertificateCollection.h"

namespace {
const char DefaultBundlePatch[] = "/opt/etc/ssl/certs/ca-certificates.crt";
} //Anonymous name space

namespace ValidationCore {
CertificatePtr RevocationCheckerBase::loadPEMFile(const char* fileName)
{
    VcoreDPL::ScopedFClose fd(fopen(fileName, "rb"));

    // no such file, return NULL
    if (!fd.Get()) {
        return CertificatePtr();
    }

    // create a new X509 certificate basing on file
    CertificatePtr cert(new Certificate(PEM_read_X509(fd.Get(),
                                                      NULL,
                                                      NULL,
                                                      NULL)));
    return cert;
}

bool RevocationCheckerBase::sortCertList(CertificateList &lCertificates)
{
    CertificateCollection collection;
    collection.load(lCertificates);

    if (collection.sort()) {
        lCertificates = collection.getChain();
        return true;
    }
    return false;
}

} // ValidationCore
