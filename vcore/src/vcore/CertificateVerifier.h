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
 * @file        CertificateVerifier.h
 * @brief       This class integrates OCSP and CRL into one module.
 */
#ifndef _VALIDATION_CORE_CERTIFICATE_VERIFIER_H_
#define _VALIDATION_CORE_CERTIFICATE_VERIFIER_H_

#include <vcore/Certificate.h>
#include <vcore/CertificateCollection.h>
#include <vcore/CachedCRL.h>
#include <vcore/CachedOCSP.h>
#include <vcore/VerificationStatus.h>

namespace ValidationCore {

class CertificateVerifier {
  public:
    explicit CertificateVerifier(bool enableOcsp, bool enableCrl);
    ~CertificateVerifier(){}

    /*
     * Run OCSP and CRL for all certificates in collection.
     * Collection must represent chain.
     *
     * Evaluate status. This function converts ocsp status set
     * into one status - the most restricted. This one ocsp status
     * and status from crl is evaluated to end result.
     *
     * Algorithm to evaluate result is represented in table:
     *
     * +--------------+-------+-------+-------+------------+---------+
     * |      OCSP    |Good   |Revoked|Unknown|Undetermined|Not      |
     * |              |       |       |       |            |supported|
     * | CRL          |       |       |       |            |         |
     * +--------------+-------+-------+-------+------------+---------+
     * | GOOD         |GOOD   |Revoked|Unknown|Undetermined|Good     |
     * +--------------+-------+-------+-------+------------+---------+
     * | REVOKED      |Revoked|Revoked|Revoked|Revoked     |Revoked  |
     * +--------------+-------+-------+-------+------------+---------+
     * | UNDETERMINED |Good   |Revoked|Unknown|Undetermined|Good     |
     * +--------------+-------+-------+-------+------------+---------+
     * | Not supported|Good   |Revoked|Unknown|Undetermined|Good     |
     * +--------------+-------+-------+-------+------------+---------+
     *
     * As Undetermind function returns VERIFICATION_STATUS_ERROR.
     */

    VerificationStatus check(CertificateCollection &certCollection) const;

    VerificationStatus checkEndEntity(
            CertificateCollectionList &certCollectionList) const;

  private:
    VerificationStatus obtainOcspStatus(
            const CertificateCollection &chain) const;
    VerificationStatus obtainCrlStatus(
            const CertificateCollection &chain) const;
    VerificationStatus getStatus(VerificationStatus ocsp,
                                 VerificationStatus crl) const;

    bool m_enableOcsp;
    bool m_enableCrl;
};

} // namespace ValidationCore

#endif // _VALIDATION_CORE_CERTIFICATE_VERIFIER_H_

