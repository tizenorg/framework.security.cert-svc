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
 * @author      Bartlomiej Grzelewski (b.grzelewski@gmail.com)
 * @version     0.1
 * @file        CertificateVerifier.cpp
 * @brief       This class integrates OCSP and CRL.
 */
#include <vcore/CertificateVerifier.h>

#include <dpl/assert.h>
#include <dpl/foreach.h>
#include <dpl/log/log.h>

namespace ValidationCore {

CertificateVerifier::CertificateVerifier(bool enableOcsp, bool enableCrl)
: m_enableOcsp(enableOcsp)
, m_enableCrl(enableCrl)
{}

VerificationStatus CertificateVerifier::check(
        CertificateCollection &certCollection) const
{
    LogDebug("== Certificate collection validation start ==");
    Assert(certCollection.isChain() && "Collection must form chain.");

    VerificationStatus statusOcsp;
    VerificationStatus statusCrl;

    if (m_enableOcsp) {
        statusOcsp = obtainOcspStatus(certCollection);
    } else {
        statusOcsp = VERIFICATION_STATUS_GOOD;
    }

    if (m_enableCrl) {
        statusCrl = obtainCrlStatus(certCollection);
    } else {
        statusCrl = VERIFICATION_STATUS_GOOD;
    }
    LogDebug("== Certificate collection validation end ==");
    return getStatus(statusOcsp, statusCrl);
}

VerificationStatus CertificateVerifier::obtainOcspStatus(
        const CertificateCollection &chain) const
{
    LogDebug("== Obtain ocsp status ==");
    CachedOCSP ocsp;
    return ocsp.check(chain);
}

VerificationStatus CertificateVerifier::obtainCrlStatus(
        const CertificateCollection &chain) const
{
    LogDebug("== Obtain crl status ==");
    CachedCRL crl;
    return crl.check(chain);
}

VerificationStatus CertificateVerifier::getStatus(
        VerificationStatus ocsp,
        VerificationStatus crl) const
{
    if (ocsp == VERIFICATION_STATUS_REVOKED ||
        crl == VERIFICATION_STATUS_REVOKED)
    {
        LogDebug("Return status: REVOKED");
        return VERIFICATION_STATUS_REVOKED;
    }

    if (ocsp == VERIFICATION_STATUS_GOOD) {
        LogDebug("Return status: GOOD");
        return VERIFICATION_STATUS_GOOD;
    }

    if (ocsp == VERIFICATION_STATUS_UNKNOWN) {
        LogDebug("Return status: UNKNOWN");
        return VERIFICATION_STATUS_UNKNOWN;
    }

    if (ocsp == VERIFICATION_STATUS_NOT_SUPPORT) {
        LogDebug("Return status: NOT_SUPPORT");
        return VERIFICATION_STATUS_GOOD;
    }

    LogDebug("Return status: ERROR");
    return VERIFICATION_STATUS_ERROR;
}

VerificationStatus CertificateVerifier::checkEndEntity(
        CertificateCollectionList &collectionList) const
{
    VerificationStatusSet statusOcsp;
    VerificationStatusSet statusCrl;

    if (m_enableOcsp) {
        CachedOCSP ocsp;
        FOREACH(it, collectionList){
            statusOcsp.add(ocsp.checkEndEntity(*it));
        }
    } else {
        statusOcsp.add(VERIFICATION_STATUS_GOOD);
    }

    if (m_enableCrl) {
        CachedCRL crl;
        FOREACH(it, collectionList){
            statusCrl.add(crl.checkEndEntity(*it));
        }
    } else {
        statusCrl.add(VERIFICATION_STATUS_GOOD);
    }
    LogDebug("== Certificate collection validateion end ==");
    return getStatus(statusOcsp.convertToStatus(), statusCrl.convertToStatus());
}

} // namespace ValidationCore
