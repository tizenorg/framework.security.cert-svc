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
#include <dpl/assert.h>
#include <openssl/x509v3.h>
#include <dpl/log/log.h>
#include <dpl/noncopyable.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <vcore/Base64.h>
#include <vcore/CertificateLoader.h>
#include <vcore/SSLContainers.h>

namespace {
const int MIN_RSA_KEY_LENGTH = 1024;
//const char *OID_CURVE_SECP256R1 = "urn:oid:1.2.840.10045.3.1.7";
} // namespace anonymous

namespace ValidationCore {
//// COMPARATOR CLASS START ////

//class CertificateLoaderECDSA : public CertificateLoader::CertificateLoaderComparator, DPL::Noncopyable {
//public:
//    CertificateLoaderECDSA(const std::string &publicKey)
//      : m_ecPublicKey(NULL)
//      , m_searchKey(NULL)
//    {
//        m_bnCtx = BN_CTX_new(); // if fails we can continue anyway
//        m_tmpPoint = BN_new();  // if fails we can continue anyway
//        m_initialized = CertificateLoader::convertBase64NodeToBigNum(publicKey, &m_searchKey);
//
//        if(!m_initialized)
//            LogError("Init failed!");
//    }
//
//    virtual bool compare(X509 *x509cert){
//        if(!m_initialized)
//            return false;
//
//        EVP_PKEY_free(m_ecPublicKey);
//
//        m_ecPublicKey = X509_get_pubkey(x509cert);
//
//        if(m_ecPublicKey == NULL)
//            return false;
//
//        if(m_ecPublicKey->type != EVP_PKEY_EC){
//            LogError("ecPublicKey has wrong type!");
//            return false;
//        }
//
//        // Pointer to internal data of ecPublicKey. Do not free!
//        EC_KEY *eckey = m_ecPublicKey->pkey.ec;
//
//        const EC_POINT *ecpoint = EC_KEY_get0_public_key(eckey);
//        const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
//
//        m_tmpPoint = EC_POINT_point2bn(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, m_tmpPoint, m_bnCtx);
//
//        if(BN_cmp(m_tmpPoint, m_searchKey) == 0)
//            return true;
//
//        return false;
//    }
//
//    ~CertificateLoaderECDSA(){
//        BN_CTX_free(m_bnCtx);
//        EVP_PKEY_free(m_ecPublicKey);
//        BN_free(m_searchKey);
//        BN_free(m_tmpPoint);
//    }
//
//private:
//    bool        m_initialized;
//    EVP_PKEY   *m_ecPublicKey;
//    BN_CTX     *m_bnCtx;
//    BIGNUM     *m_searchKey;
//    BIGNUM     *m_tmpPoint;
//};

///// COMPARETORS CLASS END /////

//// COMPARATOR RSA CLASS START ////

//class CertificateLoaderRSA : public CertificateLoader::CertificateLoaderComparator, DPL::Noncopyable {
//public:
//    CertificateLoaderRSA(const std::string &m_modulus,const std::string &m_exponent )
//      : m_rsaPublicKey(NULL)
//      , m_modulus_bn(NULL)
//      , m_exponent_bn(NULL)
//    {
//
//        m_initialized_modulus = CertificateLoader::convertBase64NodeToBigNum(m_modulus, &m_modulus_bn);
//        m_initialized_exponent = CertificateLoader::convertBase64NodeToBigNum(m_exponent, &m_exponent_bn);
//
//        if(!m_initialized_modulus || !m_initialized_exponent)
//            LogError("Init failed!");
//    }
//
//    virtual bool compare(X509 *x509cert){
//
//        if(!m_initialized_modulus || !m_initialized_exponent)
//            return false;
//
//        EVP_PKEY_free(m_rsaPublicKey);
//        m_rsaPublicKey = X509_get_pubkey(x509cert);
//
//        if(m_rsaPublicKey == NULL)
//            return false;
//
//        if(m_rsaPublicKey->type != EVP_PKEY_RSA){
//            LogInfo("rsaPublicKey has wrong type!");
//            return false;
//        }
//
//        RSA *rsa = NULL;
//        rsa = m_rsaPublicKey->pkey.rsa;
//
//        if (BN_cmp(m_modulus_bn, rsa->n) == 0 &&
//            BN_cmp(m_exponent_bn, rsa->e) == 0 ){
//            LogError ("Compare TRUE");
//            return true;
//        }
//        return false;
//    }
//
//    ~CertificateLoaderRSA(){
//        EVP_PKEY_free(m_rsaPublicKey);
//        BN_free(m_modulus_bn);
//        BN_free(m_exponent_bn);
//
//    }
//
//private:
//    bool        m_initialized_modulus;
//    bool        m_initialized_exponent;
//    EVP_PKEY   *m_rsaPublicKey;
//    BIGNUM     *m_modulus_bn;
//    BIGNUM     *m_exponent_bn;
//};

///// COMPARETORS RSA CLASS END /////

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnExponentAndModulus(const std::string &m_modulus,
        const std::string &m_exponent)
{
    (void) m_modulus;
    (void) m_exponent;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
    //    if (m_exponent.empty() || m_modulus.empty())
    //        return WRONG_ARGUMENTS;
    //
    //    CertificateLoaderRSA comparator(m_modulus,m_exponent);
    //
    //    CertificateLoaderResult result = NO_ERROR;
    //    for(int i=0; storeId[i]; ++i){
    //        result = loadCertificate(std::string(storeId[i]), &comparator);
    //
    //        if(result == ERR_NO_MORE_CERTIFICATES)
    //            continue;
    //
    //        return result;
    //    }
    //
    //    return result;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::loadCertificate(
        const std::string &storageName,
        CertificateLoader::CertificateLoaderComparator *cmp)
{
    (void) storageName;
    (void) cmp;
    LogError("Not Implemented");
    return UNKNOWN_ERROR;
    //    long int result = OPERATION_SUCCESS;
    //
    //    char storeId[CERTMGR_MAX_PLUGIN_ID_SIZE];
    //    char type[CERTMGR_MAX_CERT_TYPE_SIZE];
    //    certmgr_cert_id certId;
    //    certmgr_ctx context;
    //    certmgr_mem_buff certRetrieved;
    //    unsigned char buffer[CERTMGR_MAX_BUFFER_SIZE];
    //
    //    certmgr_cert_descriptor descriptor;
    //
    //    certRetrieved.data = buffer;
    //    certRetrieved.firstFree = 0;
    //    certRetrieved.size = CERTMGR_MAX_BUFFER_SIZE;
    //    certId.storeId = storeId;
    //    certId.type = type;
    //
    //    CERTMGR_INIT_CONTEXT((&context), (sizeof(context)))
    //
    //    strncpy(context.storeId, storageName.c_str(), storageName.size());
    //
    //    for(certRetrieved.firstFree = 0;
    //        OPERATION_SUCCESS == (result = certmgr_retrieve_certificate_from_store(&context, &certRetrieved, &certId));
    //        certRetrieved.firstFree = 0)
    //    {
    //
    //        if(OPERATION_SUCCESS!=certmgr_extract_certificate_data(&certRetrieved, &descriptor)){
    //            LogError("Extracting Certificate Data failed \n");
    //            continue;
    //        }
    //
    //        const unsigned char *ptr = certRetrieved.data;
    //
    //        X509 *x509cert = d2i_X509(NULL, &ptr, certRetrieved.size);
    //        if(x509cert == NULL){
    //            certmgr_release_certificate_data(&descriptor);
    //            LogError("Error extracting certificate (d2i_X509).");
    //            return UNKNOWN_ERROR;
    //        }
    //
    //        LogDebug("The subject of this certificate is " << descriptor.mandatory.subject);
    //        if(cmp->compare(x509cert)){
    //            LogDebug("Found match. Coping bytes: " << certRetrieved.size);
    //            m_certificatePtr = CertificatePtr(new Certificate(certRetrieved));
    //            certmgr_release_certificate_data(&descriptor);
    //            X509_free(x509cert);
    //            break;
    //        }
    //
    //        LogDebug("Release");
    //        X509_free(x509cert);
    //        certmgr_release_certificate_data(&descriptor);
    //    }
    //
    //    if(ERR_NO_MORE_CERTIFICATES == result){
    //        LogError("Certificates for given DN not found\n");
    //        return CERTIFICATE_NOT_FOUND;
    //    }
    //
    //    if(result!= OPERATION_SUCCESS){
    //        LogError("Certificate Manager Error\n");
    //        return UNKNOWN_ERROR;
    //    }
    //
    //    LogDebug("Exit");
    //    return NO_ERROR;
}

// TODO
CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnSubjectName(const std::string &subjectName)
{
    (void) subjectName;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
    //    if(subjectName.empty())
    //    {
    //        return WRONG_ARGUMENTS;
    //    }
    //
    //    long int result = OPERATION_SUCCESS;
    //
    //    char storeId[CERTMGR_MAX_PLUGIN_ID_SIZE];
    //    char type[CERTMGR_MAX_CERT_TYPE_SIZE];
    //    certmgr_cert_id certId;
    //    certmgr_ctx context;
    //    certmgr_mem_buff certRetrieved;
    //    unsigned char buffer[CERTMGR_MAX_BUFFER_SIZE];
    //
    //    certmgr_cert_descriptor descriptor;
    //
    //    certRetrieved.data = buffer;
    //    certRetrieved.firstFree = 0;
    //    certRetrieved.size = CERTMGR_MAX_BUFFER_SIZE;
    //    certId.storeId = storeId;
    //    certId.type = type;
    //
    //    CERTMGR_INIT_CONTEXT((&context), (sizeof(context)))
    //
    //    for(certRetrieved.firstFree = 0;
    //        OPERATION_SUCCESS == (result = certmgr_retrieve_certificate_from_store(&context, &certRetrieved, &certId));
    //        certRetrieved.firstFree = 0)
    //    {
    //
    //        if(OPERATION_SUCCESS!=certmgr_extract_certificate_data(&certRetrieved, &descriptor)){
    //            LogError("Extracting Certificate Data failed \n");
    //            continue;
    //        }
    //
    //        if(!strcmp(subjectName.c_str(), descriptor.mandatory.subject)){
    //            LogDebug("The subject of this certificate is " << descriptor.mandatory.subject);
    //            m_certificatePtr = CertificatePtr(new Certificate(certRetrieved));
    //            certmgr_release_certificate_data(&descriptor);
    //            break;
    //        }
    //        LogDebug("Release");
    //        certmgr_release_certificate_data(&descriptor);
    //    }
    //
    //    if(ERR_NO_MORE_CERTIFICATES == result) {
    //        LogError("Certificates for given DN not found\n");
    //        return CERTIFICATE_NOT_FOUND;
    //    }
    //    if(result!= OPERATION_SUCCESS){
    //        LogError("Certificate Manager Error\n");
    //        return UNKNOWN_ERROR;
    //    }
    //    LogDebug("Exit");
    //    return NO_ERROR;
}

// KW CertificateLoader::CertificateLoaderResult CertificateLoader::loadCertificateBasedOnIssuerName(const std::string &issuerName, const std::string &serialNumber)
// KW {
// KW     if(issuerName.empty() || serialNumber.empty())
// KW     {
// KW         return WRONG_ARGUMENTS;
// KW     }
// KW
// KW     if(m_cmBuff.data){
// KW         delete[] m_cmBuff.data;
// KW         memset(&m_cmBuff, 0, sizeof(certmgr_mem_buff));
// KW     }
// KW
// KW     LogDebug("IssuerName: " << issuerName << " serialNumber: " << serialNumber);
// KW
// KW     //used to check status of retrieved certificate
// KW     long int result = OPERATION_SUCCESS;
// KW     char storeId[CERTMGR_MAX_PLUGIN_ID_SIZE];
// KW     char type[CERTMGR_MAX_CERT_TYPE_SIZE];
// KW     certmgr_cert_id certId;
// KW     certmgr_ctx context;
// KW     certmgr_mem_buff certRetrieved;
// KW     unsigned char buffer[CERTMGR_MAX_BUFFER_SIZE];
// KW
// KW     certmgr_cert_descriptor descriptor;
// KW
// KW     certRetrieved.data = buffer;
// KW     certRetrieved.firstFree = 0;
// KW     certRetrieved.size = CERTMGR_MAX_BUFFER_SIZE;
// KW     certId.storeId = storeId;
// KW     certId.type = type;
// KW
// KW     CERTMGR_INIT_CONTEXT((&context), (sizeof(context)))
// KW
// KW     for(certRetrieved.firstFree = 0;
// KW         OPERATION_SUCCESS == (result = certmgr_retrieve_certificate_from_store(&context, &certRetrieved, &certId));
// KW         certRetrieved.firstFree = 0)
// KW     {
// KW
// KW         LogDebug("Extracting certificate from CertMgr");
// KW
// KW         if( OPERATION_SUCCESS != certmgr_extract_certificate_data(&certRetrieved, &descriptor) ){
// KW             LogError("Extracting Certificate Data failed \n");
// KW             continue;
// KW         }
// KW
// KW         LogDebug("Issuer: " << descriptor.mandatory.issuer);
// KW
// KW         const unsigned char *ptr = certRetrieved.data;
// KW         char *tmp;
// KW
// KW         X509 *x509cert = d2i_X509(NULL, &ptr, certRetrieved.size);
// KW         std::string serialNO = std::string(tmp = i2s_ASN1_INTEGER(NULL, X509_get_serialNumber(x509cert)));
// KW         OPENSSL_free(tmp);
// KW         X509_free(x509cert);
// KW
// KW         LogInfo("Certificate number found: " << serialNO);
// KW         LogInfo("Certificate number looking for: " << serialNumber);
// KW
// KW         if(!strcmp(issuerName.c_str(), descriptor.mandatory.issuer)
// KW               && serialNumber == serialNO)
// KW         {
// KW             LogError("The issuer of this certificate is " << descriptor.mandatory.issuer);
// KW
// KW             m_cmBuff.data = new unsigned char[certRetrieved.size];
// KW             m_cmBuff.firstFree = m_cmBuff.size = certRetrieved.size;
// KW             memcpy(m_cmBuff.data, certRetrieved.data, certRetrieved.size);
// KW             certmgr_release_certificate_data(&descriptor);
// KW             break;
// KW         }
// KW         certmgr_release_certificate_data(&descriptor);
// KW     }
// KW
// KW     if(ERR_NO_MORE_CERTIFICATES == result) {
// KW         LogError("Certificates not found");
// KW         return CERTIFICATE_NOT_FOUND;
// KW     }
// KW     if(result != OPERATION_SUCCESS){
// KW         LogError("Certificate Manager Error");
// KW         return UNKNOWN_ERROR;
// KW     }
// KW     return NO_ERROR;
// KW }

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateWithECKEY(const std::string &curveName,
        const std::string &publicKey)
{
    (void) curveName;
    (void) publicKey;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
    //    if(curveName != OID_CURVE_SECP256R1){
    //        LogError("Found field id: " << curveName << " Expected: " << OID_CURVE_SECP256R1);
    //        return UNSUPPORTED_CERTIFICATE_FIELD;
    //    }
    //
    //    CertificateLoaderECDSA comparator(publicKey);
    //
    //    CertificateLoaderResult result = NO_ERROR;
    //    for(int i=0; storeId[i]; ++i){
    //        result = loadCertificate(std::string(storeId[i]), &comparator);
    //
    //        if(result == ERR_NO_MORE_CERTIFICATES)
    //            continue;
    //
    //        return result;
    //    }
    //
    //    return result;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateFromRawData(const std::string &rawData)
{
    Try {
        m_certificatePtr =
            CertificatePtr(new Certificate(rawData, Certificate::FORM_BASE64));
    } Catch(Certificate::Exception::Base) {
        LogWarning("Error reading certificate by openssl.");
        return UNKNOWN_ERROR;
    }

    // Check the key length if sig algorithm is RSA
    EVP_PKEY *pKey = X509_get_pubkey(m_certificatePtr->getX509());

    if (pKey->type == EVP_PKEY_RSA) {
        RSA* pRSA = pKey->pkey.rsa;

        if (pRSA) {
            int keyLength = RSA_size(pRSA);

            // key Length (modulus) is in bytes
            keyLength <<= 3;
            LogDebug("RSA key length: " << keyLength << " bits");

            if (keyLength < MIN_RSA_KEY_LENGTH) {
                LogError(
                    "RSA key too short!" << "Has only " << keyLength << " bits");
                return CERTIFICATE_SECURITY_ERROR;
            }
        }
    }

    return NO_ERROR;
}

// DEPRACETED FUNCTION
//CertificateLoader::CertificateLoaderResult CertificateLoader::loadCertificateFromRawData(const std::string &rawData)
//{
//    certmgr_mem_buff cmBuff = {0,0,0};
//
//    long int size;
//    cmBuff.data = certmgr_util_base64_decode(const_cast<void*>(static_cast<const void*>(rawData.c_str())), rawData.size(), &size);
//
//    cmBuff.firstFree = cmBuff.size = size;
//
//    certmgr_cert_descriptor descriptor;
//
//    long int result = certmgr_extract_certificate_data(&cmBuff, &descriptor);
//
//    if (result != OPERATION_SUCCESS)
//    {
//        LogError("Unable to load certificate");
//        return UNKNOWN_ERROR;
//    }
//
//    certmgr_release_certificate_data(&descriptor);
//
//    m_certificatePtr = CertificatePtr(new Certificate(cmBuff));
//
//    // we have to use temp pointer cause d2i_x509 modifies its input
//    const unsigned char* tmpPtr = cmBuff.data;
//    X509* pCertificate = d2i_X509(NULL, &tmpPtr, cmBuff.size);
//
//    if (pCertificate)
//    {
//        SSLSmartContainer<X509> pX509(pCertificate);
//
//        // Check the key length if sig algorithm is RSA
//        EVP_PKEY *pKey = X509_get_pubkey(pX509);
//
//        if (pKey->type == EVP_PKEY_RSA)
//        {
//            RSA* pRSA = pKey->pkey.rsa;
//
//            if (pRSA)
//            {
//                int keyLength = RSA_size(pRSA);
//
//                // key Length (modulus) is in bytes
//                keyLength <<= 3;
//                LogDebug("RSA key length: " << keyLength << " bits");
//
//                if (keyLength < MIN_RSA_KEY_LENGTH)
//                {
//                    LogError("RSA key too short!" << "Has only " << keyLength << " bits");
//                    return CERTIFICATE_SECURITY_ERROR;
//                }
//            }
//        }
//    }
//
//    return NO_ERROR;
//}

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnDSAComponents(const std::string& strP,
        const std::string& strQ,
        const std::string& strG,
        const std::string& strY,
        const std::string& strJ,
        const std::string& strSeed,
        const std::string& strPGenCounter)
{
    (void) strP;
    (void) strQ;
    (void) strG;
    (void) strY;
    (void) strJ;
    (void) strSeed;
    (void) strPGenCounter;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
    //    (void)strY;
    //    (void)strJ;
    //    (void)strSeed;
    //    (void)strPGenCounter;
    //
    //    long int result = UNKNOWN_ERROR;
    //
    //    char storeId[CERTMGR_MAX_PLUGIN_ID_SIZE];
    //    char type[CERTMGR_MAX_CERT_TYPE_SIZE];
    //    certmgr_cert_id certId;
    //    certmgr_ctx context;
    //    certmgr_mem_buff certRetrieved;
    //
    //    unsigned char buffer[CERTMGR_MAX_BUFFER_SIZE];
    //
    //    certmgr_cert_descriptor descriptor;
    //
    //    certRetrieved.data = buffer;
    //    certRetrieved.firstFree = 0;
    //    certRetrieved.size = CERTMGR_MAX_BUFFER_SIZE;
    //    certId.storeId = storeId;
    //    certId.type = type;
    //
    //    CERTMGR_INIT_CONTEXT((&context), (sizeof(context)))
    //    std::string strStoreType("Operator");
    //    strncpy(context.storeId, strStoreType.c_str(),  strStoreType.length());
    //
    //    for (certRetrieved.firstFree = 0;
    //      OPERATION_SUCCESS == (result = certmgr_retrieve_certificate_from_store(&context, &certRetrieved, &certId));
    //      certRetrieved.firstFree = 0)
    //    {
    //
    //        if (OPERATION_SUCCESS != certmgr_extract_certificate_data(&certRetrieved, &descriptor))
    //        {
    //            LogDebug("unable to retrieve cert from storage");
    //            continue;
    //        }
    //
    //        X509* pCertificate = d2i_X509(NULL, (const unsigned char**) &(certRetrieved.data), certRetrieved.size);
    //
    //        if (pCertificate)
    //        {
    //            EVP_PKEY *pKey = X509_get_pubkey(pCertificate);
    //
    //            if (pKey->type == EVP_PKEY_DSA)
    //            {
    //                DSA* pDSA = pKey->pkey.dsa;
    //
    //                if (pDSA)
    //                {
    //                    BIGNUM *pDSApBigNum = NULL, *pDSAqBigNum = NULL, *pDSAgBigNum = NULL;
    //
    //                    convertBase64NodeToBigNum(strP, &pDSApBigNum);
    //                    convertBase64NodeToBigNum(strQ, &pDSAqBigNum);
    //                    convertBase64NodeToBigNum(strG, &pDSAgBigNum);
    //
    //                    if (pDSApBigNum && pDSAqBigNum && pDSAgBigNum &&
    //                      BN_cmp(pDSApBigNum, pDSA->p) == 0 &&
    //                      BN_cmp(pDSAqBigNum, pDSA->q) == 0 &&
    //                      BN_cmp(pDSAgBigNum, pDSA->g) == 0)
    //                    {
    //                        LogInfo("DSA Certificate found");
    //                        /* TODO load this certificate to m_cmBuff value */
    //                        LogError("Not implemented!");
    //
    //                        EVP_PKEY_free(pKey);
    //                        X509_free(pCertificate);
    //
    //                        BN_free(pDSApBigNum);
    //                        BN_free(pDSAqBigNum);
    //                        BN_free(pDSAgBigNum);
    //
    //                        certmgr_release_certificate_data(&descriptor);
    //                        return NO_ERROR;
    //                    }
    //
    //                    if (pDSApBigNum)
    //                    {
    //                        BN_free(pDSApBigNum);
    //                    }
    //                    if (pDSAqBigNum)
    //                    {
    //                        BN_free(pDSAqBigNum);
    //                    }
    //                    if (pDSAgBigNum)
    //                    {
    //                        BN_free(pDSAgBigNum);
    //                    }
    //
    //                }
    //                EVP_PKEY_free(pKey);
    //            }
    //            X509_free(pCertificate);
    //        }
    //        else
    //            LogError("Unable to load certificate");
    //
    //        certmgr_release_certificate_data(&descriptor);
    //    }
    //
    //    LogError("No DSA certificate with given parameters");
    //
    //    return CERTIFICATE_NOT_FOUND;
}

bool CertificateLoader::convertBase64NodeToBigNum(const std::string& strNode,
        BIGNUM** ppBigNum)
{
    (void) strNode;
    (void) ppBigNum;
    LogError("Not implemented.");
    return false;
    //    if (!ppBigNum || *ppBigNum != NULL)
    //    {
    //        LogError("Ptr variable not initialized properly!");
    //        return false;
    //    }
    //
    //    // decode base64 to binary
    //    long int binBuffLength = 0;
    //    unsigned char* binBuff = NULL;
    //
    //    binBuff = certmgr_util_base64_decode(const_cast<char*> (strNode.c_str()), strNode.length(), &binBuffLength);
    //
    //    if (!binBuff)
    //    {
    //        LogError("base64 decode failed");
    //        return false;
    //    }
    //
    //    // convert binary to bignum
    //    *ppBigNum = BN_bin2bn(binBuff, binBuffLength, *ppBigNum);
    //
    //    free(binBuff);
    //
    //    if (!(*ppBigNum))
    //    {
    //        LogError("Conversion from node to bignum failed");
    //        return false;
    //    }
    //
    //    return true;
}

// KW bool CertificateLoader::convertBigNumToBase64Node(const BIGNUM* pBigNum, std::string& strNode)
// KW {
// KW     if (!pBigNum)
// KW     {
// KW         LogError("null ptr");
// KW         return false;
// KW     }
// KW
// KW     int nNumLength = BN_num_bytes(pBigNum);
// KW     unsigned char* buffer = new unsigned char[nNumLength + 1];
// KW
// KW     // convert bignum to binary format
// KW     if (BN_bn2bin(pBigNum, buffer) < 0)
// KW     {
// KW         LogError("Conversion from bignum to binary failed");
// KW         delete []buffer;
// KW         return false;
// KW     }
// KW
// KW     char* pBase64Node = NULL;
// KW     unsigned long int buffLen = 0;
// KW     certmgr_util_base64_encode(buffer, (unsigned long int) nNumLength, &pBase64Node, &buffLen);
// KW
// KW     strNode.assign(pBase64Node, buffLen);
// KW
// KW     delete []buffer;
// KW     return true;
// KW }
} // namespace ValidationCore

