/**
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        api.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       This is part of C-api proposition for cert-svc.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <glib-object.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include <dlog.h>

#include <dpl/foreach.h>
#include <dpl/log/log.h>

#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cocsp.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/ccrl.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cprimitives.h>

#include <vcore/Base64.h>
#include <vcore/Certificate.h>
#include <vcore/CertificateCollection.h>
#include <vcore/OCSP.h>
#include <vcore/CRL.h>
#include <vcore/CRLCacheInterface.h>
#include <vcore/pkcs12.h>

using namespace ValidationCore;

namespace {

typedef std::unique_ptr<CERT_CONTEXT, std::function<int(CERT_CONTEXT*)> > ScopedCertCtx;

class CRLCacheCAPI : public CRLCacheInterface {
public:
    CRLCacheCAPI(
        CertSvcCrlCacheWrite crlWrite,
        CertSvcCrlCacheRead crlRead,
        CertSvcCrlFree crlFree,
        void *userParam)
      : m_crlWrite(crlWrite)
      , m_crlRead(crlRead)
      , m_crlFree(crlFree)
      , m_userParam(userParam)
    {}

    bool getCRLResponse(CRLCachedData *ptr){
        if (!m_crlRead || !m_crlFree)
            return false;

        char *buffer;
        int size;

        bool result = m_crlRead(
            ptr->distribution_point.c_str(),
            &buffer,
            &size,
            &(ptr->next_update_time),
            m_userParam);

        if (result) {
            ptr->crl_body.clear();
            ptr->crl_body.append(buffer, size);
            m_crlFree(buffer, m_userParam);
        }

        return result;
    }
    void setCRLResponse(CRLCachedData *ptr){
        if (m_crlWrite) {
            m_crlWrite(
                ptr->distribution_point.c_str(),
                ptr->crl_body.c_str(),
                ptr->crl_body.size(),
                ptr->next_update_time,
                m_userParam);
        }
    }

private:
    CertSvcCrlCacheWrite m_crlWrite;
    CertSvcCrlCacheRead m_crlRead;
    CertSvcCrlFree m_crlFree;
    void *m_userParam;
};

class CertSvcInstanceImpl {
public:
    CertSvcInstanceImpl()
      : m_certificateCounter(0)
      , m_idListCounter(0)
      , m_stringListCounter(0)
      , m_crlWrite(NULL)
      , m_crlRead(NULL)
      , m_crlFree(NULL)
    {}

    ~CertSvcInstanceImpl(){
        FOREACH(it, m_allocatedStringSet) {
            delete[] *it;
        }
    }

    inline void reset(){
        m_certificateCounter = 0;
        m_certificateMap.clear();
        m_idListCounter = 0;
        m_idListMap.clear();
        m_stringListCounter = 0;
        m_stringListMap.clear();

        FOREACH(it, m_allocatedStringSet) {
            delete[] *it;
        }

        m_allocatedStringSet.clear();
    }

    inline int addCert(const CertificatePtr &cert) {
        m_certificateMap[m_certificateCounter] = cert;
        return m_certificateCounter++;
    }

    inline void removeCert(const CertSvcCertificate &cert) {
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter != m_certificateMap.end()) {
            m_certificateMap.erase(iter);
        }
    }

    inline int getCertFromList(
        const CertSvcCertificateList &handler,
        int position,
        CertSvcCertificate *certificate)
    {
        auto iter = m_idListMap.find(handler.privateHandler);
        if (iter == m_idListMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        if (position >= static_cast<int>(iter->second.size())) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        certificate->privateInstance = handler.privateInstance;
        certificate->privateHandler = (iter->second)[position];
        return CERTSVC_SUCCESS;
    }

    inline int getCertListLen(const CertSvcCertificateList &handler, int *len) {
        auto iter = m_idListMap.find(handler.privateHandler);
        if (iter == m_idListMap.end() || !len) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        *len = (iter->second).size();
        return CERTSVC_SUCCESS;
    }

    inline void removeCertList(const CertSvcCertificateList &handler) {
        auto iter = m_idListMap.find(handler.privateHandler);
        if (iter != m_idListMap.end())
            m_idListMap.erase(iter);
    }

    inline int isSignedBy(const CertSvcCertificate &child,
                          const CertSvcCertificate &parent,
                          int *status)
    {
        auto citer = m_certificateMap.find(child.privateHandler);
        if (citer == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        auto piter = m_certificateMap.find(parent.privateHandler);
        if (piter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        if (citer->second->isSignedBy(piter->second)) {
            *status = CERTSVC_TRUE;
        } else {
            *status = CERTSVC_FALSE;
        }
        return CERTSVC_SUCCESS;
    }

    inline int getField(const CertSvcCertificate &cert,
                        CertSvcCertificateField field,
                        CertSvcString *buffer)
    {
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        auto certPtr = iter->second;
        DPL::OptionalString result;
        switch(field) {
            case CERTSVC_SUBJECT:
                result = DPL::OptionalString(certPtr->getOneLine());
                break;
            case CERTSVC_ISSUER:
                result = DPL::OptionalString(certPtr->getOneLine(Certificate::FIELD_ISSUER));
                break;
            case CERTSVC_SUBJECT_COMMON_NAME:
                result = certPtr->getCommonName();
                break;
            case CERTSVC_SUBJECT_COUNTRY_NAME:
                result = certPtr->getCountryName();
                break;
            case CERTSVC_SUBJECT_STATE_NAME:
                result = certPtr->getStateOrProvinceName();
                break;
            case CERTSVC_SUBJECT_ORGANIZATION_NAME:
                result = certPtr->getOrganizationName();
                break;
            case CERTSVC_SUBJECT_ORGANIZATION_UNIT_NAME:
                result = certPtr->getOrganizationalUnitName();
                break;
            case CERTSVC_SUBJECT_EMAIL_ADDRESS:
                result = certPtr->getEmailAddres();
                break;
            case CERTSVC_ISSUER_COMMON_NAME:
                result = certPtr->getCommonName(Certificate::FIELD_ISSUER);
                break;
            case CERTSVC_ISSUER_STATE_NAME:
                result = certPtr->getStateOrProvinceName(Certificate::FIELD_ISSUER);
                break;
            case CERTSVC_ISSUER_ORGANIZATION_NAME:
                result = certPtr->getOrganizationName(Certificate::FIELD_ISSUER);
                break;
            case CERTSVC_ISSUER_ORGANIZATION_UNIT_NAME:
                result = certPtr->getOrganizationalUnitName(Certificate::FIELD_ISSUER);
                break;
            case CERTSVC_VERSION:
                {
                    std::stringstream stream;
                    stream << (certPtr->getVersion()+1);
                    result = DPL::OptionalString(DPL::FromUTF8String(stream.str()));
                    break;
                }
            case CERTSVC_SERIAL_NUMBER:
                result = DPL::OptionalString(certPtr->getSerialNumberString());
                break;
            case CERTSVC_KEY_USAGE:
                result = DPL::OptionalString(certPtr->getKeyUsageString());
                break;
            case CERTSVC_KEY:
                result = DPL::OptionalString(certPtr->getPublicKeyString());
                break;
            case CERTSVC_SIGNATURE_ALGORITHM:
                result = DPL::OptionalString(certPtr->getSignatureAlgorithmString());
                break;
            default:
                break;
        }

        if (result.IsNull()) {
            buffer->privateHandler = NULL;
            buffer->privateLength = 0;
            buffer->privateInstance = cert.privateInstance;
            return CERTSVC_SUCCESS;
        }
        std::string output = DPL::ToUTF8String(*result);

        char *cstring = new char[output.size()+1];
        strncpy(cstring, output.c_str(), output.size()+1);

        buffer->privateHandler = cstring;
        buffer->privateLength = output.size();
        buffer->privateInstance = cert.privateInstance;

        m_allocatedStringSet.insert(cstring);

        return CERTSVC_SUCCESS;
    }

    inline int getNotAfter(const CertSvcCertificate &cert,
                           time_t *time)
    {
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        *time = iter->second->getNotAfter();
        return CERTSVC_SUCCESS;
    }

    inline int getNotBefore(const CertSvcCertificate &cert,
                            time_t *time)
    {
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        *time = iter->second->getNotBefore();
        return CERTSVC_SUCCESS;
    }

    inline int isRootCA(const CertSvcCertificate &cert, int *status){
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        if (iter->second->isRootCert()) {
            *status = CERTSVC_TRUE;
        } else {
            *status = CERTSVC_FALSE;
        }
        return CERTSVC_SUCCESS;
    }

    inline int getCrl(const CertSvcCertificate &cert, CertSvcStringList *handler){
        auto iter = m_certificateMap.find(cert.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        int position = m_stringListCounter++;

        std::list<std::string> temp = iter->second->getCrlUris();
        std::copy(temp.begin(),
                  temp.end(),
                  back_inserter(m_stringListMap[position]));

        handler->privateHandler = position;
        handler->privateInstance = cert.privateInstance;

        return CERTSVC_SUCCESS;
    }

    inline int getStringFromList(
        const CertSvcStringList &handler,
        int position,
        CertSvcString *buffer)
    {
        buffer->privateHandler = NULL;
        buffer->privateLength = 0;

        auto iter = m_stringListMap.find(handler.privateHandler);
        if (iter == m_stringListMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        if (position >= (int)iter->second.size()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        const std::string &data = iter->second.at(position);
        int size = data.size();
        char *cstring = new char[size+1];
        if (!cstring) {
            return CERTSVC_FAIL;
        }

        strncpy(cstring, data.c_str(), data.size()+1);

        buffer->privateHandler = cstring;
        buffer->privateLength = data.size();
        buffer->privateInstance = handler.privateInstance;

        m_allocatedStringSet.insert(cstring);

        return CERTSVC_SUCCESS;
    }

    inline int getStringListLen(
        const CertSvcStringList &handler,
        int *size)
    {
        auto iter = m_stringListMap.find(handler.privateHandler);
        if (iter == m_stringListMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        *size = (int) iter->second.size();
        return CERTSVC_SUCCESS;
    }

    inline void removeStringList(const CertSvcStringList &handler)
    {
        m_stringListMap.erase(m_stringListMap.find(handler.privateHandler));
    }

    inline void removeString(const CertSvcString &handler)
    {
        auto iter = m_allocatedStringSet.find(handler.privateHandler);
        if (iter != m_allocatedStringSet.end()) {
            delete[] *iter;
            m_allocatedStringSet.erase(iter);
        }
    }

    inline int certificateSearch(
        CertSvcInstance instance,
        CertSvcCertificateField field,
        const char *value,
        CertSvcCertificateList *handler)
    {
        int result;
        search_field fieldId = SEARCH_FIELD_END;

        switch(field){
        case CERTSVC_SUBJECT:
            fieldId = SUBJECT_STR;
            break;
        case CERTSVC_ISSUER:
            fieldId = ISSUER_STR;
            break;
        case CERTSVC_SUBJECT_COMMON_NAME:
            fieldId = SUBJECT_COMMONNAME;
            break;
        default:
            LogError("Not implemented!");
            return CERTSVC_WRONG_ARGUMENT;
        }

        ScopedCertCtx ctx(cert_svc_cert_context_init(),
                          cert_svc_cert_context_final);

        if (ctx.get() == NULL) {
            LogWarning("Error in cert_svc_cert_context_init.");
            return CERTSVC_FAIL;
        }

        LogDebug("Match string: " << value);
        result = cert_svc_search_certificate(ctx.get(), fieldId, const_cast<char*>(value));
        LogDebug("Search finished!");

        if (CERT_SVC_ERR_NO_ERROR != result) {
            LogWarning("Error during certificate search");
            return CERTSVC_FAIL;
        }

        cert_svc_filename_list *fileList = ctx.get()->fileNames;

        int listId = m_idListCounter++;
        std::vector<int> &list = m_idListMap[listId];
        handler->privateHandler = listId;
        handler->privateInstance = instance;

        for(;fileList != NULL; fileList = fileList->next) {
            ScopedCertCtx ctx2(cert_svc_cert_context_init(),
                               cert_svc_cert_context_final);
            if (ctx2.get() == NULL) {
                LogWarning("Error in cert_svc_cert_context_init.");
                return CERTSVC_FAIL;
            }

            // TODO add read_certifcate_from_file function to Certificate.h
            if (CERT_SVC_ERR_NO_ERROR !=
                cert_svc_load_file_to_context(ctx2.get(), fileList->filename))
            {
                LogWarning("Error in cert_svc_load_file_to_context");
                return CERTSVC_FAIL;
            }
            int certId = addCert(CertificatePtr(new Certificate(*(ctx2.get()->certBuf))));
            list.push_back(certId);
        }
        return CERTSVC_SUCCESS;
    }

    inline int sortCollection(CertSvcCertificate *certificate_array, int size) {
        if (size < 2) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        for(int i=1; i<size; ++i) {
            if (certificate_array[i-1].privateInstance.privatePtr
                != certificate_array[i].privateInstance.privatePtr)
            {
                return CERTSVC_WRONG_ARGUMENT;
            }
        }

        CertificateList certList;
        std::map<Certificate*,int> translator;

        for(int i=0; i<size; ++i) {
            int pos = certificate_array[i].privateHandler;
            auto cert = m_certificateMap.find(pos);
            if (cert == m_certificateMap.end()) {
                return CERTSVC_WRONG_ARGUMENT;
            }
            translator[cert->second.Get()] = pos;
            certList.push_back(cert->second);
        }

        CertificateCollection collection;
        collection.load(certList);

        if (!collection.sort()) {
            return CERTSVC_FAIL;
        }

        auto chain = collection.getChain();

        int i=0;
        for (auto iter = chain.begin(); iter != chain.end() && i<size; ++iter, ++i) {
            certificate_array[i].privateHandler = translator[iter->Get()];
        }

        return CERTSVC_SUCCESS;
    }

    inline int getX509Copy(const CertSvcCertificate &certificate, X509** cert)
    {
        auto it = m_certificateMap.find(certificate.privateHandler);
        if (it == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        *cert = X509_dup(it->second->getX509());
        return CERTSVC_SUCCESS;
    }

    inline int saveToFile(const CertSvcCertificate &certificate,
                          const char *location)
    {
        auto it = m_certificateMap.find(certificate.privateHandler);
        if (it == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        FILE *out;
        if (NULL == (out = fopen(location, "w"))) {
            return CERTSVC_FAIL;
        }
        if (0 == i2d_X509_fp(out, it->second->getX509())) {
            fclose(out);
            return CERTSVC_FAIL;
        }
        fclose(out);
        return CERTSVC_SUCCESS;
    }

    inline int ocspCheck(const CertSvcCertificate *chain,
                         int chain_size,
                         const CertSvcCertificate *trusted,
                         int trusted_size,
                         const char *url,
                         int *status)
    {
        auto instance = chain[0].privateInstance.privatePtr;

        for(int i=1; i<chain_size; ++i) {
            if (instance != chain[i].privateInstance.privatePtr)
            {
                return CERTSVC_WRONG_ARGUMENT;
            }
        }
        CertificateList chainList, trustedList;

        for(int i=0; i<chain_size; ++i) {
            auto cert = m_certificateMap.find(chain[i].privateHandler);
            if (cert == m_certificateMap.end()) {
                return CERTSVC_WRONG_ARGUMENT;
            }
            chainList.push_back(cert->second);
        }

        for(int i=0; i<trusted_size; ++i) {
            if (instance != trusted[i].privateInstance.privatePtr)
            {
                return CERTSVC_WRONG_ARGUMENT;
            }
        }

        for(int i=0; i<trusted_size; ++i) {
            auto cert = m_certificateMap.find(trusted[i].privateHandler);
            if (cert == m_certificateMap.end()) {
                return CERTSVC_WRONG_ARGUMENT;
            }
            trustedList.push_back(cert->second);
        }

        OCSP ocsp;
//        ocsp.setDigestAlgorithmForCertId(OCSP::SHA1);
//        ocsp.setDigestAlgorithmForRequest(OCSP::SHA1);
        ocsp.setTrustedStore(trustedList);

        if (url) {
            ocsp.setUseDefaultResponder(true);
            ocsp.setDefaultResponder(url);
        }

        CertificateCollection collection;
        collection.load(chainList);
        if (!collection.sort()) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        chainList = collection.getChain();

        VerificationStatusSet statusSet = ocsp.validateCertificateList(chainList);

        int ret = 0;
        if (statusSet.contains(VERIFICATION_STATUS_GOOD)) {
            ret |= CERTSVC_OCSP_GOOD;
        }
        if (statusSet.contains(VERIFICATION_STATUS_REVOKED)) {
            ret |= CERTSVC_OCSP_REVOKED;
        }
        if (statusSet.contains(VERIFICATION_STATUS_UNKNOWN)) {
            ret |= CERTSVC_OCSP_UNKNOWN;
        }
        if (statusSet.contains(VERIFICATION_STATUS_VERIFICATION_ERROR)) {
            ret |= CERTSVC_OCSP_VERIFICATION_ERROR;
        }
        if (statusSet.contains(VERIFICATION_STATUS_NOT_SUPPORT)) {
            ret |= CERTSVC_OCSP_NO_SUPPORT;
        }
        if (statusSet.contains(VERIFICATION_STATUS_ERROR)) {
            ret |= CERTSVC_OCSP_ERROR;
        }

        *status = ret;
        return CERTSVC_SUCCESS;
    }

    inline int verify(
        CertSvcCertificate certificate,
        CertSvcString &message,
        CertSvcString &signature,
        const char *algorithm,
        int *status)
    {
        int result = CERTSVC_FAIL;

        if (!status) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        auto it = m_certificateMap.find(certificate.privateHandler);
        if (it == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        OpenSSL_add_all_digests();

        int temp;
        EVP_MD_CTX* mdctx = NULL;
        const EVP_MD * md = NULL;
        X509 *cert = it->second->getX509();
        EVP_PKEY *pkey = NULL;

        if (cert == NULL) {
            goto err;
        }

        pkey = X509_get_pubkey(cert);

        if (pkey == NULL) {
            goto err;
        }

        if (algorithm == NULL) {
            md = EVP_get_digestbyobj(cert->cert_info->signature->algorithm);
        } else {
            md = EVP_get_digestbyname(algorithm);
        }

        if (md == NULL) {
            result = CERTSVC_INVALID_ALGORITHM;
            goto err;
        }

        mdctx = EVP_MD_CTX_create();

        if (mdctx == NULL) {
            goto err;
        }

        if (EVP_VerifyInit_ex(mdctx, md, NULL) != 1) {
            goto err;
        }

        if (EVP_VerifyUpdate(mdctx, message.privateHandler, message.privateLength) != 1) {
            goto err;
        }

        temp = EVP_VerifyFinal(mdctx,
            reinterpret_cast<unsigned char*>(signature.privateHandler),
            signature.privateLength,
            pkey);

        if (temp == 0) {
            *status = CERTSVC_INVALID_SIGNATURE;
            result = CERTSVC_SUCCESS;
        } else if (temp == 1) {
            *status = CERTSVC_SUCCESS;
            result = CERTSVC_SUCCESS;
        }

    err:
        if (mdctx != NULL)
            EVP_MD_CTX_destroy(mdctx);
        if (pkey != NULL)
            EVP_PKEY_free(pkey);
        return result;
    }

    inline int base64Encode(
        const CertSvcString &message,
        CertSvcString *base64)
    {
        if (!base64) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        std::string info(message.privateHandler, message.privateLength);
        Base64Encoder base;
        base.reset();
        base.append(info);
        base.finalize();
        info = base.get();
        char *ptr = new char[info.size()+1];
        memcpy(ptr, info.c_str(), info.size()+1);
        m_allocatedStringSet.insert(ptr);
        base64->privateHandler = ptr;
        base64->privateLength = info.size();
        base64->privateInstance = message.privateInstance;
        return CERTSVC_SUCCESS;
    }

    int base64Decode(
        const CertSvcString &base64,
        CertSvcString *message)
    {
        if (!message) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        std::string info(base64.privateHandler, base64.privateLength);
        Base64Decoder base;
        base.reset();
        base.append(info);
        if (!base.finalize()) {
            return CERTSVC_FAIL;
        }
        info = base.get();
        char *ptr = new char[info.size()+1];
        memcpy(ptr, info.c_str(), info.size()+1);
        m_allocatedStringSet.insert(ptr);
        message->privateHandler = ptr;
        message->privateLength = info.size();
        message->privateInstance = base64.privateInstance;
        return CERTSVC_SUCCESS;
    }

    inline int stringNew(
        CertSvcInstance &instance,
        const char *str,
        int size,
        CertSvcString *output)
    {
        if (!output || size < 0) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        int allocSize = size;

        if (allocSize == 0 || str[allocSize-1] != 0)
            allocSize++;

        char *ptr = new char[allocSize];
        memcpy(ptr, str, size);
        ptr[allocSize-1] = 0;

        output->privateHandler = ptr;
        output->privateLength = size;
        output->privateInstance = instance;

        m_allocatedStringSet.insert(ptr);

        return CERTSVC_SUCCESS;
    }

    inline void setCRLFunction(
        CertSvcCrlCacheWrite writePtr,
        CertSvcCrlCacheRead readPtr,
        CertSvcCrlFree freePtr)
    {
        m_crlWrite = writePtr;
        m_crlRead = readPtr;
        m_crlFree = freePtr;
    }

    inline int crlCheck(
        CertSvcCertificate certificate,
        CertSvcCertificate *trustedStore,
        int storeSize,
        int force,
        int *status,
        void *userParam)
    {
        for(int i=1; i<storeSize; ++i) {
            if (certificate.privateInstance.privatePtr
                != trustedStore[i].privateInstance.privatePtr)
            {
                return CERTSVC_WRONG_ARGUMENT;
            }
        }

        CRL crl(new CRLCacheCAPI(m_crlWrite, m_crlRead, m_crlFree, userParam));

        for (int i=0; i<storeSize; ++i) {
            auto iter = m_certificateMap.find(trustedStore[i].privateHandler);
            if (iter == m_certificateMap.end()) {
                return CERTSVC_WRONG_ARGUMENT;
            }
            crl.addToStore(iter->second);
        }

        auto iter = m_certificateMap.find(certificate.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        if (iter->second->getCrlUris().empty()) {
            *status = CERTSVC_CRL_NO_SUPPORT;
            return CERTSVC_SUCCESS;
        }
        crl.updateList(iter->second, force ? CRL::UPDATE_ON_DEMAND: CRL::UPDATE_ON_EXPIRED);
        CRL::RevocationStatus st = crl.checkCertificate(iter->second);
        *status = 0;

        if (!st.isCRLValid) {
            *status |= CERTSVC_CRL_VERIFICATION_ERROR;
            return CERTSVC_SUCCESS;
        }

        if (st.isRevoked) {
            *status |= CERTSVC_CRL_REVOKED;
        } else {
            *status |= CERTSVC_CRL_GOOD;
        }

        return CERTSVC_SUCCESS;
    }

    inline int certificateVerify(
        CertSvcCertificate certificate,
        CertSvcCertificate *trusted,
        int trustedSize,
        CertSvcCertificate *untrusted,
        int untrustedSize,
        int *status)
    {
        if (!trusted || !status) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        auto iter = m_certificateMap.find(certificate.privateHandler);
        if (iter == m_certificateMap.end()) {
            return CERTSVC_WRONG_ARGUMENT;
        }

        X509 *cert = iter->second->getX509();
        X509_STORE *store = X509_STORE_new();
        STACK_OF(X509) *ustore = sk_X509_new_null();

        for (int i=0; i<trustedSize; ++i) {
            auto iter = m_certificateMap.find(trusted[i].privateHandler);
            if (iter == m_certificateMap.end()) {
                X509_STORE_free(store);
                sk_X509_free(ustore);
                return CERTSVC_WRONG_ARGUMENT;
            }
            X509_STORE_add_cert(store, iter->second->getX509());
        }

        for (int i=0; i<untrustedSize; ++i) {
            auto iter = m_certificateMap.find(untrusted[i].privateHandler);
            if (iter == m_certificateMap.end()) {
                X509_STORE_free(store);
                sk_X509_free(ustore);
                return CERTSVC_WRONG_ARGUMENT;
            }
            if (sk_X509_push(ustore, iter->second->getX509()) == 0)
            {
                break;
            }
        }
        X509_STORE_CTX context;
        X509_STORE_CTX_init(&context, store, cert, ustore);
        int result = X509_verify_cert(&context);
        X509_STORE_CTX_cleanup(&context);
        X509_STORE_free(store);
        sk_X509_free(ustore);

        if (result == 1) {
            *status = CERTSVC_SUCCESS;
        } else {
            *status = CERTSVC_FAIL;
        }
        return CERTSVC_SUCCESS;
    }

    inline int pkcsNameIsUnique(
        CertSvcString pfxIdString,
        int *is_unique)
    {
      gboolean exists;
      int result = c_certsvc_pkcs12_alias_exists(pfxIdString.privateHandler, &exists);
      *is_unique = !exists;
      return result;
    }

    inline int pkcsImport(
        CertSvcString path,
        CertSvcString pass,
        CertSvcString pfxIdString)
    {
      return c_certsvc_pkcs12_import(path.privateHandler, pass.privateHandler, pfxIdString.privateHandler);
    }

    inline int getPkcsIdList(
        CertSvcInstance &instance,
        CertSvcStringList *handler)
    {
      gchar **aliases;
      gsize i, naliases;
      std::vector<std::string> output;
      int result;

      result = c_certsvc_pkcs12_aliases_load(&aliases, &naliases);
      if(result != CERTSVC_SUCCESS)
        return result;
      for(i = 0; i < naliases; i++)
        output.push_back(std::string(aliases[i]));
      c_certsvc_pkcs12_aliases_free(aliases);

      int position = m_stringListCounter++;
      m_stringListMap[position] = output;

      handler->privateHandler = position;
      handler->privateInstance = instance;
      return CERTSVC_SUCCESS;
    }

    inline int pkcsHasPassword(
        CertSvcString filepath,
        int *has_password)
    {
      return c_certsvc_pkcs12_has_password(filepath.privateHandler, has_password);
    }

    inline int getPkcsPrivateKey(
        CertSvcString pfxIdString,
        char **buffer,
        size_t *size)
    {
        return c_certsvc_pkcs12_private_key_load(pfxIdString.privateHandler, buffer, size);
    }

    inline int getPkcsCertificateList(
        CertSvcInstance &instance,
        CertSvcString &pfxIdString,
        CertSvcCertificateList *handler)
    {
      gchar **certs;
      gsize i, ncerts;
      std::vector<CertificatePtr> certPtrVector;
      std::vector<int> listId;
      int result;

      result = c_certsvc_pkcs12_load_certificates(pfxIdString.privateHandler, &certs, &ncerts);
      if(result != CERTSVC_SUCCESS)
        return result;
      for(i = 0; i < ncerts; i++) {
        ScopedCertCtx context(cert_svc_cert_context_init(), cert_svc_cert_context_final);
        if(cert_svc_load_file_to_context(context.get(), certs[i]) != CERT_SVC_ERR_NO_ERROR) {
          c_certsvc_pkcs12_free_certificates(certs);
          return CERTSVC_IO_ERROR;
        }
        else
          certPtrVector.push_back(CertificatePtr(new Certificate(*(context->certBuf))));
      }
      if(ncerts > 0)
          c_certsvc_pkcs12_free_certificates(certs);

      FOREACH(it, certPtrVector) {
        listId.push_back(addCert(*it));
      }

      int position = m_idListCounter++;
      m_idListMap[position] = listId;

      handler->privateInstance = instance;
      handler->privateHandler = position;

      return result;
    }

    inline int pkcsDelete(CertSvcString pfxIdString)
    {
      return c_certsvc_pkcs12_delete(pfxIdString.privateHandler);
    }

private:
    int m_certificateCounter;
    std::map<int, CertificatePtr> m_certificateMap;

    int m_idListCounter;
    std::map<int, std::vector<int> > m_idListMap;

    int m_stringListCounter;
    std::map<int, std::vector<std::string> > m_stringListMap;

    std::set<char *> m_allocatedStringSet;

    CertSvcCrlCacheWrite m_crlWrite;
    CertSvcCrlCacheRead m_crlRead;
    CertSvcCrlFree m_crlFree;
};

inline CertSvcInstanceImpl *impl(CertSvcInstance instance) {
    return static_cast<CertSvcInstanceImpl*>(instance.privatePtr);
}

} // namespace anonymous

int certsvc_instance_new(CertSvcInstance *instance) {
    static int init = 1;
    if (init) {
        SSL_library_init();     // required by message verification
        OpenSSL_add_all_digests();
        g_type_init();          // required by libsoup/ocsp
        init = 0;
    }
    try {
        instance->privatePtr =
            reinterpret_cast<void*>(new CertSvcInstanceImpl);
        if (instance->privatePtr)
            return CERTSVC_SUCCESS;
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

void certsvc_instance_reset(CertSvcInstance instance) {
    impl(instance)->reset();
}

void certsvc_instance_free(CertSvcInstance instance) {
    delete impl(instance);
}

int certsvc_certificate_new_from_file(
        CertSvcInstance instance,
        const char *location,
        CertSvcCertificate *certificate)
{
    try {
        ScopedCertCtx context(cert_svc_cert_context_init(),
                              cert_svc_cert_context_final);

        int result = cert_svc_load_file_to_context(context.get(), location);

        switch(result) {
            case CERT_SVC_ERR_INVALID_PARAMETER: return CERTSVC_WRONG_ARGUMENT;
            case CERT_SVC_ERR_INVALID_OPERATION: return CERTSVC_FAIL;
            case CERT_SVC_ERR_MEMORY_ALLOCATION: return CERTSVC_BAD_ALLOC;
            default:;
        }

        CertificatePtr cert(new Certificate(*(context->certBuf)));

        certificate->privateInstance = instance;
        certificate->privateHandler = impl(instance)->addCert(cert);

        return CERTSVC_SUCCESS;
    // TODO support for std exceptions
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_new_from_memory(
        CertSvcInstance instance,
        const unsigned char *memory,
        int len,
        CertSvcCertificateForm form,
        CertSvcCertificate *certificate)
{
    try {
        Certificate::FormType formType;
        std::string binary((char*)memory, len);

        if (CERTSVC_FORM_DER == form) {
            formType = Certificate::FORM_DER;
        } else {
            formType = Certificate::FORM_BASE64;
        }

        CertificatePtr cert(new Certificate(binary, formType));

        certificate->privateInstance = instance;
        certificate->privateHandler = impl(instance)->addCert(cert);
        return CERTSVC_SUCCESS;
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

void certsvc_certificate_free(CertSvcCertificate certificate)
{
    impl(certificate.privateInstance)->removeCert(certificate);
}

int certsvc_certificate_save_file(
        CertSvcCertificate certificate,
        const char *location)
{
    return impl(certificate.privateInstance)->saveToFile(certificate, location);
}

int certsvc_certificate_search(
        CertSvcInstance instance,
        CertSvcCertificateField field,
        const char *value,
        CertSvcCertificateList *handler)
{
    try {
        return impl(instance)->certificateSearch(instance, field, value, handler);
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_list_get_one(
        CertSvcCertificateList handler,
        int position,
        CertSvcCertificate *certificate)
{
    return impl(handler.privateInstance)->
        getCertFromList(handler,position, certificate);
}

int certsvc_certificate_list_get_length(
        CertSvcCertificateList handler,
        int *size)
{
    return impl(handler.privateInstance)->getCertListLen(handler, size);
}

void certsvc_certificate_list_free(CertSvcCertificateList handler)
{
    impl(handler.privateInstance)->removeCertList(handler);
}

int certsvc_certificate_is_signed_by(
        CertSvcCertificate child,
        CertSvcCertificate parent,
        int *status)
{
    if (child.privateInstance.privatePtr == parent.privateInstance.privatePtr) {
        return impl(child.privateInstance)->isSignedBy(child, parent, status);
    }
    return CERTSVC_WRONG_ARGUMENT;
}

int certsvc_certificate_get_string_field(
        CertSvcCertificate certificate,
        CertSvcCertificateField field,
        CertSvcString *buffer)
{
    try {
        return impl(certificate.privateInstance)->getField(certificate, field, buffer);
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_get_not_after(
        CertSvcCertificate certificate,
        time_t *result)
{
    try {
        return impl(certificate.privateInstance)->getNotAfter(certificate, result);
    } catch(...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_get_not_before(
        CertSvcCertificate certificate,
        time_t *result)
{
    try {
        return impl(certificate.privateInstance)->getNotBefore(certificate, result);
    } catch(...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_is_root_ca(CertSvcCertificate certificate, int *status)
{
    return impl(certificate.privateInstance)->isRootCA(certificate, status);
}

int certsvc_certificate_get_crl_distribution_points(
        CertSvcCertificate certificate,
        CertSvcStringList *handler)
{
    try {
        return impl(certificate.privateInstance)->getCrl(certificate, handler);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_string_list_get_one(
        CertSvcStringList handler,
        int position,
        CertSvcString *buffer)
{
    try {
        return impl(handler.privateInstance)->getStringFromList(handler, position, buffer);
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_string_list_get_length(
        CertSvcStringList handler,
        int *size)
{
    return impl(handler.privateInstance)->getStringListLen(handler, size);
}

void certsvc_string_list_free(CertSvcStringList handler)
{
    impl(handler.privateInstance)->removeStringList(handler);
}

void certsvc_string_free(CertSvcString string)
{
    impl(string.privateInstance)->removeString(string);
}

void certsvc_string_to_cstring(
        CertSvcString string,
        const char **buffer,
        int *len)
{
    if (buffer) {
        *buffer = string.privateHandler;
    }
    if (len) {
        *len = string.privateLength;
    }
}

int certsvc_certificate_chain_sort(
        CertSvcCertificate *certificate_array,
        int size)
{
    try {
        if (!certificate_array) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        return impl(certificate_array[0].privateInstance)->
            sortCollection(certificate_array, size);
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_dup_x509(CertSvcCertificate certificate, X509 **cert)
{
    try {
        return impl(certificate.privateInstance)->getX509Copy(certificate, cert);
    } catch (...) {}
    return CERTSVC_FAIL;
}

void certsvc_certificate_free_x509(X509 *x509)
{
    X509_free(x509);
}

int certsvc_pkcs12_dup_evp_pkey(
    CertSvcInstance instance,
    CertSvcString alias,
    EVP_PKEY** pkey)
{
    char *buffer;
    size_t size;

    int result = certsvc_pkcs12_private_key_dup(
        instance,
        alias,
        &buffer,
        &size);

    if (result != CERTSVC_SUCCESS) {
        LogError("Error in certsvc_pkcs12_private_key_dup");
        return result;
    }

    BIO *b = BIO_new(BIO_s_mem());

    if ((int)size != BIO_write(b, buffer, size)) {
        LogError("Error in BIO_write");
        BIO_free_all(b);
        certsvc_pkcs12_private_key_free(buffer);
        return CERTSVC_FAIL;
    }

    certsvc_pkcs12_private_key_free(buffer);

    *pkey = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);

    BIO_free_all(b);

    if (*pkey) {
        return CERTSVC_SUCCESS;
    }

    LogError("Result is null. Openssl REASON code is: "
        << ERR_GET_REASON(ERR_peek_last_error()));

    return CERTSVC_FAIL;
}

void certsvc_pkcs12_free_evp_pkey(EVP_PKEY* pkey)
{
    EVP_PKEY_free(pkey);
}

int certsvc_ocsp_check(
    CertSvcCertificate *chain,
    int chain_size,
    CertSvcCertificate *trusted,
    int trusted_size,
    const char *url,
    int *status)
{
    try {
        if (!chain || !trusted) {
            return CERTSVC_WRONG_ARGUMENT;
        }
        return impl(chain[0].privateInstance)->
            ocspCheck(chain,
                      chain_size,
                      trusted,
                      trusted_size,
                      url,
                      status);
    } catch (std::bad_alloc &) {
        return CERTSVC_BAD_ALLOC;
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_message_verify(
    CertSvcCertificate certificate,
    CertSvcString message,
    CertSvcString signature,
    const char *algorithm,
    int *status)
{
    try {
        return impl(certificate.privateInstance)->verify(
            certificate,
            message,
            signature,
            algorithm,
            status);
    } catch(...) {}
    return CERTSVC_FAIL;
}

int certsvc_base64_encode(CertSvcString message, CertSvcString *base64)
{
    try {
        return impl(message.privateInstance)->base64Encode(message, base64);
    } catch(...) {}
    return CERTSVC_FAIL;
}

int certsvc_base64_decode(CertSvcString base64, CertSvcString *message)
{
    try {
        return impl(base64.privateInstance)->base64Decode(base64, message);
    } catch(...) {}
    return CERTSVC_FAIL;
}

int certsvc_string_new(
    CertSvcInstance instance,
    const char *url,
    int size,
    CertSvcString *output)
{
    try {
        return impl(instance)->stringNew(instance, url, size, output);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_string_not_managed(
    CertSvcInstance instance,
    const char *url,
    int size,
    CertSvcString *output)
{
    if (!output) {
        return CERTSVC_WRONG_ARGUMENT;
    }
    output->privateHandler = const_cast<char*>(url);
    output->privateLength = size;
    output->privateInstance = instance;
    return CERTSVC_SUCCESS;
}

void certsvc_crl_cache_functions(
    CertSvcInstance instance,
    CertSvcCrlCacheWrite writePtr,
    CertSvcCrlCacheRead readPtr,
    CertSvcCrlFree freePtr)
{
    impl(instance)->setCRLFunction(writePtr, readPtr, freePtr);
}

int certsvc_crl_check(
    CertSvcCertificate certificate,
    CertSvcCertificate *trustedStore,
    int storeSize,
    int force,
    int *status,
    void *userParam)
{
    try {
        return impl(certificate.privateInstance)->crlCheck(
            certificate,
            trustedStore,
            storeSize,
            force,
            status,
            userParam);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_certificate_verify(
    CertSvcCertificate certificate,
    CertSvcCertificate *trusted,
    int trustedSize,
    CertSvcCertificate *untrusted,
    int untrustedSize,
    int *status)
{
    try {
        return impl(certificate.privateInstance)->certificateVerify(
            certificate,
            trusted,
            trustedSize,
            untrusted,
            untrustedSize,
            status);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_alias_exists(CertSvcInstance instance,
    CertSvcString pfxIdString,
    int *is_unique)
{
    try {
      return impl(instance)->pkcsNameIsUnique(pfxIdString, is_unique);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_import_from_file(CertSvcInstance instance,
    CertSvcString path,
    CertSvcString password,
    CertSvcString pfxIdString)
{
    try {
      return impl(instance)->pkcsImport(path, password, pfxIdString);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_get_id_list(
    CertSvcInstance instance,
    CertSvcStringList *pfxIdStringList)
{
    try {
        return impl(instance)->getPkcsIdList(
            instance,
            pfxIdStringList);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_has_password(
    CertSvcInstance instance,
    CertSvcString filepath,
    int *has_password)
{
    try {
        return impl(instance)->pkcsHasPassword(
            filepath,
            has_password);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_load_certificate_list(
    CertSvcInstance instance,
    CertSvcString pfxIdString,
    CertSvcCertificateList *certificateList)
{
    try {
        return impl(instance)->getPkcsCertificateList(
            instance,
            pfxIdString,
            certificateList);
    } catch (...) {}
    return CERTSVC_FAIL;
}

int certsvc_pkcs12_private_key_dup(
    CertSvcInstance instance,
    CertSvcString pfxIdString,
    char **buffer,
    size_t *size)
{
    try {
        return impl(instance)->getPkcsPrivateKey(pfxIdString, buffer, size);
    } catch (...) {}
    return CERTSVC_FAIL;
}

void certsvc_pkcs12_private_key_free(
    char *buffer)
{
    delete[] buffer;
}

int certsvc_pkcs12_delete(
    CertSvcInstance instance,
    CertSvcString pfxIdString)
{
    try {
        return impl(instance)->pkcsDelete(pfxIdString);
    } catch (...) {}
    return CERTSVC_FAIL;
}
