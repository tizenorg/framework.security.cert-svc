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
/*
 * @file        Certificate.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.1
 * @brief
 */
#ifndef _VALIDATION_CORE_CERTIFICATE_H_
#define _VALIDATION_CORE_CERTIFICATE_H_

#include <list>
#include <set>
#include <string>
#include <vector>
#include <ctime>
#include <memory>

#include <openssl/x509.h>

#include <vcore/exception.h>

#include <cert-service.h>

extern "C" {
struct x509_st;
typedef struct x509_st X509;
struct X509_name_st;
typedef struct X509_name_st X509_NAME;
}

namespace ValidationCore {

class Certificate;

typedef std::shared_ptr<Certificate> CertificatePtr;
typedef std::list<CertificatePtr> CertificateList;

class Certificate : public std::enable_shared_from_this<Certificate> {
public:
    class Exception {
    public:
        VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base);
        VCORE_DECLARE_EXCEPTION_TYPE(Base, OpensslInternalError);
    };

    typedef std::vector<unsigned char> Fingerprint;

    // ascii string
    typedef std::string AltName;
    typedef std::set<AltName> AltNameSet;

    enum FingerprintType
    {
        FINGERPRINT_MD5,
        FINGERPRINT_SHA1
    };
    enum FieldType
    {
        FIELD_ISSUER,
        FIELD_SUBJECT
    };

    enum FormType
    {
        FORM_DER,
        FORM_BASE64
    };

    explicit Certificate(X509 *cert);

    explicit Certificate(cert_svc_mem_buff &buffer);

    explicit Certificate(const std::string &der,
                         FormType form = FORM_DER);

    ~Certificate();

    // It returns pointer to internal structure!
    // Do not free this pointer!
    X509 *getX509(void) const;

    std::string getDER(void) const;

    std::string getBase64(void) const;

    // This const is cheating here because you have no
    // guarantee that X509_get_subject_name will not
    // change X509 object.
    bool isSignedBy(const CertificatePtr &parent) const;

    Fingerprint getFingerprint(FingerprintType type) const;

    // getName uses deprecated functions. Usage is strongly discouraged.
    // utf8 string
    std::string getOneLine(FieldType type = FIELD_SUBJECT) const;
    std::string getCommonName(FieldType type = FIELD_SUBJECT) const;
    std::string getCountryName(FieldType type = FIELD_SUBJECT) const;
    std::string getStateOrProvinceName(FieldType type = FIELD_SUBJECT) const;
    std::string getLocalityName(FieldType type = FIELD_SUBJECT) const;
    std::string getOrganizationName(FieldType type = FIELD_SUBJECT) const;
    std::string getOrganizationalUnitName(FieldType type = FIELD_SUBJECT) const;
    std::string getEmailAddres(FieldType type = FIELD_SUBJECT) const;
    std::string getOCSPURL() const;


    // Openssl supports 9 types of alternative name filed.
    // 4 of them are "string similar" types so it is possible
    // to create more generic function.
    AltNameSet getAlternativeNameDNS() const;

    time_t getNotAfter() const;

    time_t getNotBefore() const;

    ASN1_TIME* getNotAfterTime() const;

    ASN1_TIME* getNotBeforeTime() const;

    /**
     * @brief This is convenient function.
     *
     * @details It can't be const function (however it doesn't change internal
     * object). For details see #isSignedBy() function description.
     */
    bool isRootCert();

    /**
     * @brief Gets list of CRL distribution's points URIs
     */
    std::list<std::string> getCrlUris() const;

    long getVersion() const;

    // utf8 string
    std::string getSerialNumberString() const;
    std::string getKeyUsageString() const;
    std::string getSignatureAlgorithmString() const;
    std::string getPublicKeyString() const;

    /*
     * 0 - not CA
     * 1 - CA
     * 2 - deprecated and not used
     * 3 - older version of CA
     * 4 - older version of CA
     * 5 - netscape CA
     */
    int isCA() const;

    static std::string FingerprintToColonHex(
            const Fingerprint &fingerprint);

protected:
    X509_NAME *getX509Name(FieldType type) const;

    // utf8 string
    std::string getField(FieldType type, int fieldNid) const;

    X509 *m_x509;
};
} // namespace ValidationCore

#endif // _VALIDATION_CORE_CERTIFICATE_H_
