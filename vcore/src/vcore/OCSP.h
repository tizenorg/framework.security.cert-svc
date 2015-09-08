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
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.5
 * @file        OCPS.h
 * @brief       This class is used to hide OCSP implementation.
 */

#ifndef _VALIDATION_CORE_OCSP_H_
#define _VALIDATION_CORE_OCSP_H_

#include <ctime>

#include <vcore/Certificate.h>
#include <vcore/CertificateCollection.h>
#include <vcore/VerificationStatus.h>

namespace ValidationCore {

class OCSPImpl;

class OCSP {
public:
    OCSP(const OCSP &) = delete;
    const OCSP &operator=(const OCSP &) = delete;

    OCSP();

    VerificationStatus checkEndEntity(const CertificateCollection &certList);

    enum DigestAlgorithm
    {
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512
    };

    /**
     * Sets digest algorithm for certid in ocsp request
     */
    void setDigestAlgorithmForCertId(DigestAlgorithm alg);

    /**
     * Sets digest algorithm for certid in ocsp request
     */
    void setDigestAlgorithmForRequest(DigestAlgorithm alg);

    void setTrustedStore(const CertificateList& certs);

    VerificationStatusSet validateCertificateList(const CertificateList &certs);

    VerificationStatus validateCertificate(CertificatePtr argCert,
                                           CertificatePtr argIssuer);

    void setDefaultResponder(const char* uri);

    void setUseDefaultResponder(bool value);

    /**
     * @return time when response will become invalid - for list of
     * certificates, this is the minimum of all validities; value is
     * valid only for not-revoked certificates (non error validation result)
     */
    time_t getResponseValidity();

    virtual ~OCSP();
private:
    OCSPImpl *m_impl;

};

} // namespace ValidationCore

#endif //ifndef _VALIDATION_CORE_OCSP_H_
