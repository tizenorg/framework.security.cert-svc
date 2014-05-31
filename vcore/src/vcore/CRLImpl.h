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
 * @file        CRLImpl.h
 * @brief       Routines for certificate validation over CRL
 */

#ifndef _VALIDATION_CORE_ENGINE_CRLIMPL_H_
#define _VALIDATION_CORE_ENGINE_CRLIMPL_H_

#include <dpl/exception.h>
#include <dpl/shared_ptr.h>
#include <dpl/noncopyable.h>
#include <dpl/log/log.h>

#include <openssl/x509.h>

#include <vcore/CRL.h>
#include <vcore/Certificate.h>
#include <vcore/CertificateCollection.h>
#include <vcore/SoupMessageSendBase.h>
#include <vcore/VerificationStatus.h>
#include <vcore/CRLCacheInterface.h>
#include <vcore/TimeConversion.h>

namespace ValidationCore {

class CRLImpl : DPL::Noncopyable
{
  protected:
    X509_STORE *m_store;
    X509_LOOKUP *m_lookup;
    CRLCacheInterface *m_crlCache;

    class CRLData : DPL::Noncopyable
    {
      public:
        //TODO: change to SharedArray when available
        char *buffer;
        size_t length;
        std::string uri;

        CRLData(char* _buffer,
                size_t _length,
                const std::string &_uri) :
            buffer(_buffer),
            length(_length),
            uri(_uri)
        {
        }

        CRLData(const SoupWrapper::SoupMessageSendBase::MessageBuffer &mBuff,
                const std::string &mUri)
        : uri(mUri)
        {
            buffer = new char[mBuff.size()];
            length = mBuff.size();
            memcpy(buffer, &mBuff[0], mBuff.size());
        }

        ~CRLData()
        {
            LogInfo("Delete buffer");
            delete[] buffer;
        }
    };
    typedef DPL::SharedPtr<CRLData> CRLDataPtr;

    CRLDataPtr getCRL(const std::string &uri) const;
    CRLDataPtr downloadCRL(const std::string &uri);
    X509_STORE_CTX *createContext(const CertificatePtr &argCert);
    void updateCRL(const CRLDataPtr &crl);
    X509_CRL *convertToInternal(const CRLDataPtr &crl) const;
    CRL::StringList getCrlUris(const CertificatePtr &argCert);
    bool isPEMFormat(const CRLDataPtr &crl) const;
    bool verifyCRL(X509_CRL *crl,
                   const CertificatePtr &cert);
    void cleanup();
    bool isOutOfDate(const CRLDataPtr &crl) const;

    friend class CachedCRL;
  public:
    CRLImpl(CRLCacheInterface *ptr);
    ~CRLImpl();

    /**
     * @brief Checks if given certificate is revoked.
     *
     * @details This function doesn't update CRL list. If related CRL
     * is out of date the #isCRLValid return parameter is set to false.
     *
     * @param[in] argCert The certificate to check against revocation.
     * @return RevocationStatus.isRevoked True when certificate is revoked,
     *          false otherwise.
     *         RevocationStatus.isCRLValid True if related CRL has not expired,
     *          false otherwise.
     */
    CRL::RevocationStatus checkCertificate(const CertificatePtr &argCert);

    /**
     * @brief Checks if any certificate from certificate chain is revoked.
     *
     * @details This function doesn't update CRL lists. If any of related
     * CRL is out of date the #isCRLValid parameter is set to true.
     * This function adds valid certificates from the chain to internal storage
     * map so they'll be available in further check operations for current
     * CRL object.
     *
     * @param[in] argCert The certificate chain to check against revocation.
     * @return RevocationStatus.isRevoked True when any from certificate chain
     *          is revoked, false otherwise.
     *         RevocationStatus.isCRLValid True if all of related CRLs has
     *          not expired, false otherwise.
     */
    CRL::RevocationStatus checkCertificateChain(CertificateCollection certChain);

    VerificationStatus checkEndEntity(CertificateCollection &chain);

    /**
     * @brief Updates CRL related with given certificate.
     *
     * @details This function updates CRL list related with given certificate.
     * If CRL related with given certificate is not stored in database
     * then this function will download CRL and store it in database.
     *
     * @param[in] argCert The certificate for which the CRL will be updated
     * @param[in] updatePolicy Determine when CRL will be downloaded and updated
     * @return True when CRL for given certificate was updated successfully,
     *          false otherwise.
     */
    bool updateList(const CertificatePtr &argCert,
                    const CRL::UpdatePolicy updatePolicy);

    /**
     * @brief Updates CRL related with given certificates.
     *
     * @details This function updates CRL lists related with given certificates.
     * If CRL related with given certificate is not stored in database
     * then this function will download CRL and store it in database.
     *
     * @param[in] collection The certificate collection for which the CRL will
     *            be updated
     * @param[in] updatePolicy Determine when CRL will be downloaded and updated
     * @return True when CRL for given certificate was updated successfully,
     *          false otherwise.
     */
    bool updateList(const CertificateCollection &collection,
                    const CRL::UpdatePolicy updatePolisy);

    /**
     * @brief Add certificates to trusted certificates store.
     *
     * @param[in] collection The certificate collection which will be
     *            added to known certificate store.
     */
    void addToStore(const CertificateCollection &collection);

    /**
     * @brief Add one certificate to trusted certificates store.
     *
     * @param[in] collection The certificate collection which will be
     *            added to known certificate store.
     */
    void addToStore(const CertificatePtr &argCert);
};

} // ValidationCore

#endif // _VALIDATION_CORE_ENGINE_CRLIMPL_H_
