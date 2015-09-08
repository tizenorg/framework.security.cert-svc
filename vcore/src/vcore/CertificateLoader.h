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
#ifndef _CERTIFICATELOADER_H_
#define _CERTIFICATELOADER_H_

#include <string>
#include <string.h>

#include <dpl/noncopyable.h>
#include <openssl/ssl.h>

#include <cert-service.h>

#include <vcore/Certificate.h>

namespace ValidationCore {
class CertificateLoader : public VcoreDPL::Noncopyable
{
  public:
    class CertificateLoaderComparator
    {
      public:
        virtual bool compare(X509 *x509cert) = 0;
        virtual ~CertificateLoaderComparator()
        {
        }
    };

    enum CertificateLoaderResult
    {
        NO_ERROR,
        CERTIFICATE_NOT_FOUND,
        UNSUPPORTED_CERTIFICATE_FIELD,
        WRONG_ARGUMENTS,
        CERTIFICATE_SECURITY_ERROR,                  //!< there are some issues with certificate security (i.e. key too short)
        UNKNOWN_ERROR
    };

    CertificateLoader()
    {
    }

    virtual ~CertificateLoader()
    {
    }

    CertificateLoaderResult loadCertificate(const std::string& storage,
            CertificateLoaderComparator *cmp);

    CertificateLoaderResult loadCertificateBasedOnSubjectName(
            const std::string &subjectName);
    CertificateLoaderResult loadCertificateBasedOnExponentAndModulus(
            const std::string &m_modulus,
            const std::string  &m_exponent);
    // KW     CertificateLoaderResult loadCertificateBasedOnIssuerName(const std::string &isserName,
    // KW       const std::string &serialNumber);

    CertificateLoaderResult loadCertificateFromRawData(
            const std::string &rawData);

    CertificateLoaderResult loadCertificateBasedOnDSAComponents(
            const std::string& strP,
            const std::string& strQ,
            const std::string& strG,
            const std::string& strY,
            const std::string& strJ,
            const std::string& strSeed,
            const std::string& strPGenCounter);

    CertificateLoaderResult loadCertificateWithECKEY(
            const std::string &curveName,
            const std::string &publicKey);

    /**
     * converts base64 encoded node to SSL bignum
     * allocates mem on *ppBigNum, don't forget to free it later with BN_free!
     * returns conversion status
     */
    static bool convertBase64NodeToBigNum(const std::string& strNode,
            BIGNUM** ppBigNum);

    /*
     * encodes SSL bignum into base64 octstring
     * returns conversion status
     */
    // KW     static bool convertBigNumToBase64Node(const BIGNUM* pBigNum, std::string& strNode);

    CertificatePtr getCertificatePtr() const
    {
        return m_certificatePtr;
    }
  private:
    CertificatePtr m_certificatePtr;
};
} // namespace ValidationCore

#endif // _CERTIFICATELOADER_H_
