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
 * @author      Tomasz Morawski(t.morawski@samsung.com)
 * @author      Michal Ciepielski(m.ciepielski@samsung.com)
 * @author      Piotr Marcinkiewicz(p.marcinkiew@samsung.com)
 * @author      Bartlomiej Grzelewski(b.grzelewski@samsung.com)
 * @version     0.4
 * @file        OCPS.h
 * @brief       Routines for certificate validation over OCSP
 */

#ifndef _VALIDATION_CORE_OCSPIMPL_H_
#define _VALIDATION_CORE_OCSPIMPL_H_

#include <vcore/OCSP.h>

#include <string>
#include <vector>
#include <list>

#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <libsoup/soup.h>

#include <dpl/assert.h>
#include <dpl/exception.h>
#include <dpl/optional_typedefs.h>


#include <vcore/scoped_gpointer.h>
#include <vcore/OCSPCertMgrUtil.h>
#include <vcore/CertificateCollection.h>
#include <vcore/CertificateStorage.h>
#include <vcore/VerificationStatus.h>
#include <vcore/SSLContainers.h>
#include <vcore/SoupMessageSendBase.h>
#include <vcore/SoupMessageSendSync.h>
#include <vcore/TimeConversion.h>
/*
 * The WRT MUST NOT allow installation of widgets with revoked signatures.
 *
 * The WRT MUST NOT allow use of widgets with revoked signatures.
 *
 * The WRT MUST support checking for revocation of widget signatures via
 * OCSP [RFC 2560] at widget installation time, according to the following:
 *
 * At widget installation time, the WRT shall make several attempts
 * (5 attempts at 6 seconds apart recommended) to establish contact with
 * the OCSP server.
 *
 * If connectivity is successful and the application is validated, the
 * installation process shall continue.
 *
 * If connectivity is successful and if the widget signature is
 * determined to be revoked, the WRT shall issue a suitable error message
 * and cancel installation.
 *
 * If connectivity is successful and revocation status is unknown or if
 * connectivity is unsuccessful, the user must be notified that the
 * widget was unable to be installed as trusted - the certification of
 * the widget signature has not been validated -, and prompt the user to allow
 * the user to install the widget as an untrusted application, or reject
 * the installation.
 *
 * The WRT MUST support checking for revocation of widget signatures via OCSP
 * [RFC 2560] at widget runtime.
 *
 * The WRT MUST support OCSP access policy.
 */

namespace ValidationCore {

class OCSPImpl
{
  public:
    static const char* DEFAULT_RESPONDER_URI_ENV;

    VerificationStatus checkEndEntity(const CertificateCollection &certList);
    OCSPImpl();

    /**
     * Sets digest algorithm for certid in ocsp request
     */
    void setDigestAlgorithmForCertId(OCSP::DigestAlgorithm alg);

    /**
     * Sets digest algorithm for certid in ocsp request
     */
    void setDigestAlgorithmForRequest(OCSP::DigestAlgorithm alg);

    void setTrustedStore(const CertificateList& certs);

    VerificationStatusSet validateCertificateList(const CertificateList &certs);

    VerificationStatus validateCertificate(CertificatePtr argCert,
                                           CertificatePtr argIssuer);

    void setDefaultResponder(const char* uri)
    {
        Assert(uri);
        m_strResponderURI = DPL::FromUTF8String(uri);
    }

    void setUseDefaultResponder(bool value)
    {
        m_bUseDefResponder = value;
    }

    /**
     * @return time when response will become invalid - for list of
     * certificates, this is the minimum of all validities; value is
     * valid only for not-revoked certificates (non error validation result)
     */
    time_t getResponseValidity()
    {
        return m_responseValidity;
    }

  private:
    typedef WRT::ScopedGPointer<SoupSession> ScopedSoupSession;
    typedef WRT::ScopedGPointer<SoupMessage> ScopedSoupMessage;

    void handleInvalidResponse(int result);
    void sendHTTPRequest(ScopedSoupSession& session,
                         ScopedSoupMessage& msg,
                         const char* host,
                         const char* port,
                         const char* path,
                         char* requestBuffer,
                         size_t reqestSize);
    void sendRequest(const std::string& uri,
                     char* requestBuffer,
                     size_t requestSize,
                     char** responseBuffer,
                     size_t* responseSize);

    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, ConnectionError)
        DECLARE_EXCEPTION_TYPE(Base, CertificateRevoked)
        DECLARE_EXCEPTION_TYPE(Base, CertificateUnknown)
        DECLARE_EXCEPTION_TYPE(Base, VerificationError)
        DECLARE_EXCEPTION_TYPE(Base, RetrieveCertFromStoreError)
        DECLARE_EXCEPTION_TYPE(Base, VerificationNotSupport)
    };

    const EVP_MD* m_pCertIdDigestAlg;
    const EVP_MD* m_pRequestDigestAlg;

    typedef std::pair<char*, size_t> HttpResponseBuffer;

    SoupWrapper::SoupMessageSendBase::RequestStatus sendOcspRequest(
    	OCSP_REQUEST* argRequest,
    	const DPL::OptionalString& argUri);

    //! Validates a single certificate
    /*!
     * @param cert The certificate to check
     * @param issuer A certificate used to sign the certificate to check.
     */

    struct CreateRequestResult
    {
        bool success;
        OCSP_REQUEST* ocspRequest;
        OCSP_CERTID* ocspCertId;
        CreateRequestResult(bool argSuccess = false,
                            OCSP_REQUEST* argOcspRequest = NULL,
                            OCSP_CERTID* argOcspCertId = NULL) :
            success(argSuccess),
            ocspRequest(argOcspRequest),
            ocspCertId(argOcspCertId)
        {
        }
    };

    //! Creates a OCSP request
    /*!
     * @param request Returns created OCSP_REQUEST
     * @param id Returns CertId that is used to find proper OCSP result in
     * the OCSP response (@see checkRevocationStatus for more details).
     *
     */
    CreateRequestResult createRequest(CertificatePtr argCert,
                                      CertificatePtr argIssuer);

    OCSP_CERTID* addSerial(CertificatePtr argCert,
                           CertificatePtr argIssuer);

    void validateResponse(OCSP_REQUEST* argRequest,
                          OCSP_RESPONSE* argResponse,
                          OCSP_CERTID* argCertId);

    //! Create a X509 store
    bool verifyResponse(OCSP_BASICRESP* argResponse);

    void  checkRevocationStatus(OCSP_BASICRESP* argBasicResponse,
                                OCSP_CERTID* argCertId);

    typedef std::pair<bool, OCSP_RESPONSE*> OcspResponse;

    OcspResponse convertToResponse();

    time_t m_responseValidity;
    bool m_bUseNonce;
    bool m_bUseDefResponder;
    DPL::String m_strResponderURI;
    bool m_bSignRequest;
    EVP_PKEY*                       m_pSignKey;
    CertificatePtr m_pSignCert;
    SSLSmartContainer <X509_STORE>  m_pTrustedStore;
    SoupWrapper::SoupMessageSendSync m_soupMessage;
};

} // ValidationCore

#endif // _VALIDATION_CORE_OCSPIMPL_H_
