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
 * @author      Bartlomiej Grzelewski(b.grzelewski@samsung.com)
 * @version     0.5
 * @file        OCPS.cpp
 * @brief       This class is used for hide OCSP implementation.
 */

#include <vcore/OCSPImpl.h>

namespace ValidationCore {

OCSP::OCSP()
  : m_impl(new OCSPImpl())
{}

OCSP::~OCSP()
{
    delete m_impl;
}

ValidationCore::VerificationStatusSet OCSP::validateCertificateList(
    const CertificateList &certs)
{
    return m_impl->validateCertificateList(certs);
}

VerificationStatus OCSP::checkEndEntity(
        const CertificateCollection &chain)
{
    return m_impl->checkEndEntity(chain);
}

VerificationStatus OCSP::validateCertificate(CertificatePtr argCert,
                                             CertificatePtr argIssuer)
{
    return m_impl->validateCertificate(argCert, argIssuer);
}

void OCSP::setDigestAlgorithmForCertId(DigestAlgorithm alg) {
    return m_impl->setDigestAlgorithmForCertId(alg);
}

void OCSP::setDigestAlgorithmForRequest(DigestAlgorithm alg) {
    return m_impl->setDigestAlgorithmForRequest(alg);
}

void OCSP::setTrustedStore(const CertificateList& certs) {
    m_impl->setTrustedStore(certs);
}

void OCSP::setDefaultResponder(const char *uri) {
    m_impl->setDefaultResponder(uri);
}

void OCSP::setUseDefaultResponder(bool value) {
    m_impl->setUseDefaultResponder(value);
}

time_t OCSP::getResponseValidity() {
    return m_impl->getResponseValidity();
}

} // namespace ValidationCore
