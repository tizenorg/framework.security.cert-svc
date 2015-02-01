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
 * @version     0.2
 * @file        CRLImpl.h
 * @brief       Routines for certificate validation over CRL
 */

#include <vcore/CRL.h>
#include <vcore/CRLImpl.h>

#include <set>
#include <algorithm>

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <dpl/log/log.h>
#include <dpl/assert.h>
#include <dpl/exception.h>
#include <dpl/db/orm.h>
#include <dpl/foreach.h>

#include <vcore/Base64.h>
#include <vcore/Certificate.h>
#include <vcore/SoupMessageSendSync.h>
#include <vcore/CRLCacheInterface.h>

namespace {
const char *CRL_LOOKUP_DIR_1 = "/usr/share/cert-svc/ca-certs/code-signing/wac";
const char *CRL_LOOKUP_DIR_2 = "/usr/share/cert-svc/certs/code-signing/wac";
} //anonymous namespace

namespace ValidationCore {

CRL::StringList CRLImpl::getCrlUris(const CertificatePtr &argCert)
{
    CRL::StringList result = argCert->getCrlUris();

    if (!result.empty()) {
        return result;
    }
    LogInfo("No distribution points found. Getting from CA cert.");
    X509_STORE_CTX *ctx = createContext(argCert);
    X509_OBJECT obj;

    //Try to get distribution points from CA certificate
    int retVal = X509_STORE_get_by_subject(ctx, X509_LU_X509,
                                           X509_get_issuer_name(argCert->
                                                                    getX509()),
                                           &obj);
    X509_STORE_CTX_free(ctx);
    if (0 >= retVal) {
        LogError("No dedicated CA certificate available");
        return result;
    }
    CertificatePtr caCert(new Certificate(obj.data.x509));
    X509_OBJECT_free_contents(&obj);
    return caCert->getCrlUris();
}

CRLImpl::CRLImpl(CRLCacheInterface *ptr)
  : m_crlCache(ptr)
{
    Assert(m_crlCache != NULL);

    LogInfo("CRL storage initialization.");
    m_store = X509_STORE_new();
    if (!m_store) {
        LogError("Failed to create new store.");
        ThrowMsg(CRLException::StorageError,
                 "Not possible to create new store.");
    }
    m_lookup = X509_STORE_add_lookup(m_store, X509_LOOKUP_hash_dir());
    if (!m_lookup) {
        cleanup();
        LogError("Failed to add hash dir lookup");
        ThrowMsg(CRLException::StorageError,
                 "Not possible to add hash dir lookup.");
    }
    // Add hash dir pathname for CRL checks
    bool retVal = X509_LOOKUP_add_dir(m_lookup,
                                      CRL_LOOKUP_DIR_1, X509_FILETYPE_PEM) == 1;
    retVal &= retVal && (X509_LOOKUP_add_dir(m_lookup, CRL_LOOKUP_DIR_1,
                                             X509_FILETYPE_ASN1) == 1);
    retVal &= retVal && (X509_LOOKUP_add_dir(m_lookup, CRL_LOOKUP_DIR_2,
                                             X509_FILETYPE_PEM) == 1);
    retVal &= retVal && (X509_LOOKUP_add_dir(m_lookup, CRL_LOOKUP_DIR_2,
                                             X509_FILETYPE_ASN1) == 1);
    if (!retVal) {
        LogError("Failed to add lookup dir for PEM files.");
        cleanup();
        ThrowMsg(CRLException::StorageError,
                 "Failed to add lookup dir for PEM files.");
    }
    LogInfo("CRL storage initialization complete.");
}

CRLImpl::~CRLImpl()
{
    cleanup();
    delete m_crlCache;
}

void CRLImpl::cleanup()
{
    LogInfo("Free CRL storage");
    // STORE is responsible for LOOKUP release
    //    X509_LOOKUP_free(m_lookup);
    X509_STORE_free(m_store);
}

CRL::RevocationStatus CRLImpl::checkCertificate(const CertificatePtr &argCert)
{
    CRL::RevocationStatus retStatus = {false, false};
    int retVal = 0;
    CRL::StringList crlUris = getCrlUris(argCert);
    FOREACH(it, crlUris) {
        CRLDataPtr crl = getCRL(*it);
        if (!crl) {
            LogDebug("CRL not found for URI: " << *it);
            continue;
        }
        X509_CRL *crlInternal = convertToInternal(crl);

        //Check date
        if (X509_CRL_get_nextUpdate(crlInternal)) {
            retVal = X509_cmp_current_time(
                    X509_CRL_get_nextUpdate(crlInternal));
            retStatus.isCRLValid = retVal > 0;
        } else {
            // If nextUpdate is not set assume it is actual.
            retStatus.isCRLValid = true;
        }
        LogInfo("CRL valid: " << retStatus.isCRLValid);
        X509_REVOKED rev;
        rev.serialNumber = X509_get_serialNumber(argCert->getX509());
        // sk_X509_REVOKED_find returns index if serial number is found on list
        retVal = sk_X509_REVOKED_find(crlInternal->crl->revoked, &rev);
        X509_CRL_free(crlInternal);
        retStatus.isRevoked = retVal != -1;
        LogInfo("CRL revoked: " << retStatus.isRevoked);

        if (!retStatus.isRevoked && isOutOfDate(crl)) {
            LogDebug("Certificate is not Revoked, but CRL is outOfDate.");
            continue;
        }

        return retStatus;
    }
    // If there is no CRL for any of URIs it means it's not possible to
    // tell anything about revocation status but it's is not an error.
    return retStatus;
}

CRL::RevocationStatus CRLImpl::checkCertificateChain(CertificateCollection
                                                 certChain)
{
    if (!certChain.sort()) {
        LogError("Certificate list doesn't create chain.");
        ThrowMsg(CRLException::InvalidParameter,
                 "Certificate list doesn't create chain.");
    }

    CRL::RevocationStatus ret;
    ret.isCRLValid = true;
    ret.isRevoked = false;
    const CertificateList &certList = certChain.getChain();
    FOREACH(it, certList) {
        if (!(*it)->isRootCert()) {
            LogInfo("Certificate common name: " << *((*it)->getCommonName()));
            CRL::RevocationStatus certResult = checkCertificate(*it);
            ret.isCRLValid &= certResult.isCRLValid;
            ret.isRevoked |= certResult.isRevoked;
            if (ret.isCRLValid && !ret.isRevoked) {
                addToStore(*it);
            }
            if (ret.isRevoked) {
                return ret;
            }
        }
    }
    return ret;
}

VerificationStatus CRLImpl::checkEndEntity(CertificateCollection &chain)
{
    if (!chain.sort() && !chain.empty()) {
        LogInfo("Could not find End Entity certificate. "
                "Collection does not form chain.");
        return VERIFICATION_STATUS_ERROR;
    }
    CertificateList::const_iterator iter = chain.begin();
    CRL::RevocationStatus stat = checkCertificate(*iter);
    if (stat.isRevoked) {
        return VERIFICATION_STATUS_REVOKED;
    }
    if (stat.isCRLValid) {
        return VERIFICATION_STATUS_GOOD;
    }
    return VERIFICATION_STATUS_ERROR;
}

void CRLImpl::addToStore(const CertificatePtr &argCert)
{
    X509_STORE_add_cert(m_store, argCert->getX509());
}

bool CRLImpl::isOutOfDate(const CRLDataPtr &crl) const {
    X509_CRL *crlInternal = convertToInternal(crl);

    bool result = false;
    if (X509_CRL_get_nextUpdate(crlInternal)) {
        if (0 > X509_cmp_current_time(X509_CRL_get_nextUpdate(crlInternal))) {
            result = true;
        } else {
            result = false;
        }
    } else {
        result = true;
    }
    X509_CRL_free(crlInternal);
    return result;
}

bool CRLImpl::updateList(const CertificatePtr &argCert,
    const CRL::UpdatePolicy updatePolicy)
{
    LogInfo("Update CRL for certificate");

    // Retrieve distribution points
    CRL::StringList crlUris = getCrlUris(argCert);
    FOREACH(it, crlUris) {
        // Try to get CRL from database
        LogInfo("Getting CRL for URI: " << *it);

        bool downloaded = false;

        CRLDataPtr crl;

        // If updatePolicy == UPDATE_ON_DEMAND we dont care
        // about data in cache. New crl must be downloaded.
        if (updatePolicy == CRL::UPDATE_ON_EXPIRED) {
            crl = getCRL(*it);
        }

        if (!!crl && isOutOfDate(crl)) {
            LogDebug("Crl out of date - downloading.");
            crl = downloadCRL(*it);
            downloaded = true;
        }

        if (!crl) {
            LogDebug("Crl not found in cache - downloading.");
            crl = downloadCRL(*it);
            downloaded = true;
        }

        if (!crl) {
            LogDebug("Failed to obtain CRL. URL: " << *it);
            continue;
        }

        if (!!crl && isOutOfDate(crl)) {
            LogError("CRL out of date. Broken URL: " << *it);
        }

        // Make X509 internal structure
        X509_CRL *crlInternal = convertToInternal(crl);

        //Check if CRL is signed
        if (!verifyCRL(crlInternal, argCert)) {
            LogError("Failed to verify CRL. URI: " << crl->uri);
            X509_CRL_free(crlInternal);
            return false;
        }
        X509_CRL_free(crlInternal);

        if (downloaded) {
            updateCRL(crl);
        }
        return true;
    }

    return false;
}

void CRLImpl::addToStore(const CertificateCollection &collection)
{
    FOREACH(it, collection){
        addToStore(*it);
    }
}

bool CRLImpl::updateList(const CertificateCollection &collection,
    CRL::UpdatePolicy updatePolicy)
{
    bool failed = false;

    FOREACH(it, collection){
        failed |= !updateList(*it, updatePolicy);
    }

    return !failed;
}

bool CRLImpl::verifyCRL(X509_CRL *crl,
                    const CertificatePtr &cert)
{
    X509_OBJECT obj;
    X509_STORE_CTX *ctx = createContext(cert);

    /* get issuer certificate */
    int retVal = X509_STORE_get_by_subject(ctx, X509_LU_X509,
                                           X509_CRL_get_issuer(crl), &obj);
    X509_STORE_CTX_free(ctx);
    if (0 >= retVal) {
        LogError("Unknown CRL issuer certificate!");
        return false;
    }

    /* extract public key and verify signature */
    EVP_PKEY *pkey = X509_get_pubkey(obj.data.x509);
    X509_OBJECT_free_contents(&obj);
    if (!pkey) {
        LogError("Failed to get issuer's public key.");
        return false;
    }
    retVal = X509_CRL_verify(crl, pkey);
    EVP_PKEY_free(pkey);
    if (0 > retVal) {
        LogError("Failed to verify CRL.");
        return false;
    } else if (0 == retVal) {
        LogError("CRL is invalid");
        return false;
    }
    LogInfo("CRL is valid.");
    return true;
}

bool CRLImpl::isPEMFormat(const CRLDataPtr &crl) const
{
    const char *pattern = "-----BEGIN X509 CRL-----";
    std::string content(crl->buffer, crl->length);
    if (content.find(pattern) != std::string::npos) {
        LogInfo("CRL is in PEM format.");
        return true;
    }
    LogInfo("CRL is in DER format.");
    return false;
}

X509_CRL *CRLImpl::convertToInternal(const CRLDataPtr &crl) const
{
    //At this point it's not clear does crl have DER or PEM format
    X509_CRL *ret = NULL;
    if (isPEMFormat(crl)) {
        BIO *bmem = BIO_new_mem_buf(crl->buffer, crl->length);
        if (!bmem) {
            LogError("Failed to allocate memory in BIO");
            ThrowMsg(CRLException::InternalError,
                     "Failed to allocate memory in BIO");
        }
        ret = PEM_read_bio_X509_CRL(bmem, NULL, NULL, NULL);
        BIO_free_all(bmem);
    } else {
        //If it's not PEM it must be DER format
        std::string content(crl->buffer, crl->length);
        const unsigned char *buffer =
            reinterpret_cast<unsigned char*>(crl->buffer);
        ret = d2i_X509_CRL(NULL, &buffer, crl->length);
    }
    if (!ret) {
        LogError("Failed to convert to internal structure");
        ThrowMsg(CRLException::InternalError,
                 "Failed to convert to internal structure");
    }
    return ret;
}

X509_STORE_CTX *CRLImpl::createContext(const CertificatePtr &argCert)
{
    X509_STORE_CTX *ctx;
    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        ThrowMsg(CRLException::StorageError, "Failed to create new context.");
    }
    X509_STORE_CTX_init(ctx, m_store, argCert->getX509(), NULL);
    return ctx;
}

CRLImpl::CRLDataPtr CRLImpl::downloadCRL(const std::string &uri)
{
    using namespace SoupWrapper;

    char *cport = 0, *chost = 0,*cpath = 0;
    int use_ssl = 0;

    if (!OCSP_parse_url(const_cast<char*>(uri.c_str()),
                        &chost,
                        &cport,
                        &cpath,
                        &use_ssl))
    {
        LogWarning("Error in OCSP_parse_url");
        return CRLDataPtr();
    }

    std::string host = chost;
    if (cport) {
        host += ":";
        host += cport;
    }

    free(cport);
    free(chost);
    free(cpath);

    SoupMessageSendSync message;
    message.setHost(uri);
    message.setHeader("Host", host);

    if (SoupMessageSendSync::REQUEST_STATUS_OK != message.sendSync()) {
        LogWarning("Error in sending network request.");
        return CRLDataPtr();
    }

    SoupMessageSendBase::MessageBuffer mBuffer = message.getResponse();
    return CRLDataPtr(new CRLData(mBuffer,uri));
}

CRLImpl::CRLDataPtr CRLImpl::getCRL(const std::string &uri) const
{
    CRLCachedData cachedCrl;
    cachedCrl.distribution_point = uri;
    if (!(m_crlCache->getCRLResponse(&cachedCrl))) {
        LogInfo("CRL not present in database. URI: " << uri);
        return CRLDataPtr();
    }

    std::string body = cachedCrl.crl_body;

    LogInfo("CRL found in database.");
    //TODO: remove when ORM::blob available
    //Encode buffer to base64 format to store in database

    Base64Decoder decoder;
    decoder.append(body);
    if (!decoder.finalize()) {
        LogError("Failed to decode base64 format.");
        ThrowMsg(CRLException::StorageError, "Failed to decode base64 format.");
    }
    std::string crlBody = decoder.get();

    std::unique_ptr<char[]> bodyBuffer(new char[crlBody.length()]);
    crlBody.copy(bodyBuffer.get(), crlBody.length());
    return CRLDataPtr(new CRLData(bodyBuffer.release(), crlBody.length(),
                                  uri));
}

void CRLImpl::updateCRL(const CRLDataPtr &crl)
{
    //TODO: remove when ORM::blob available
    //Encode buffer to base64 format to store in database
    Base64Encoder encoder;
    if (!crl || !crl->buffer) {
        ThrowMsg(CRLException::InternalError, "CRL buffer is empty");
    }
    encoder.append(std::string(crl->buffer, crl->length));
    encoder.finalize();
    std::string b64CRLBody = encoder.get();

    time_t nextUpdateTime = 0;
    X509_CRL *crlInternal = convertToInternal(crl);

    if (X509_CRL_get_nextUpdate(crlInternal)) {
        asn1TimeToTimeT(X509_CRL_get_nextUpdate(crlInternal),
                        &nextUpdateTime);
    }

    X509_CRL_free(crlInternal);
    //Update/insert crl body
    CRLCachedData data;
    data.distribution_point = crl->uri;
    data.crl_body = b64CRLBody;
    data.next_update_time = nextUpdateTime;

    m_crlCache->setCRLResponse(&data);
}

} // namespace ValidationCore
