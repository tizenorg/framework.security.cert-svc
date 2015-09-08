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
 * @file
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */

#include <vcore/CertificateConfigReader.h>

#include <dpl/assert.h>

#include <cstdlib>

namespace {
const std::string XML_EMPTY_NAMESPACE = "";

const std::string TOKEN_CERTIFICATE_SET = "CertificateSet";
const std::string TOKEN_CERTIFICATE_DOMAIN = "CertificateDomain";
const std::string TOKEN_FINGERPRINT_SHA1 = "FingerprintSHA1";

const std::string TOKEN_ATTR_NAME = "name";
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
const std::string TOKEN_ATTR_URL_NAME = "ocspUrl";
#endif
const std::string TOKEN_VALUE_TIZEN_DEVELOPER = "tizen-developer";
const std::string TOKEN_VALUE_TIZEN_TEST = "tizen-test";
const std::string TOKEN_VALUE_TIZEN_VERIFY = "tizen-verify";
const std::string TOKEN_VALUE_VISIBILITY_PUBLIC = "tizen-public";
const std::string TOKEN_VALUE_VISIBILITY_PARTNER = "tizen-partner";
const std::string TOKEN_VALUE_VISIBILITY_PARTNER_OPERATOR = "tizen-partner-operator";
const std::string TOKEN_VALUE_VISIBILITY_PARTNER_MANUFACTURER = "tizen-partner-manufacturer";
const std::string TOKEN_VALUE_VISIBILITY_PLATFORM = "tizen-platform";

int hexCharToInt(char c)
{
    if (c >= 'a' && c <= 'f') {
        return 10 + static_cast<int>(c) - 'a';
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + static_cast<int>(c) - 'A';
    }
    if (c >= '0' && c <= '9') {
        return static_cast<int>(c) - '0';
    }
    return c;
}
} // anonymous namespace

namespace ValidationCore {
CertificateConfigReader::CertificateConfigReader()
  : m_certificateDomain(0)
  , m_parserSchema(this)
{
    m_parserSchema.addBeginTagCallback(
        TOKEN_CERTIFICATE_SET,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::blankFunction);

    m_parserSchema.addBeginTagCallback(
        TOKEN_CERTIFICATE_DOMAIN,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::tokenCertificateDomain);

    m_parserSchema.addBeginTagCallback(
        TOKEN_FINGERPRINT_SHA1,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::blankFunction);

    m_parserSchema.addEndTagCallback(
        TOKEN_CERTIFICATE_SET,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::blankFunction);

    m_parserSchema.addEndTagCallback(
        TOKEN_CERTIFICATE_DOMAIN,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::blankFunction);

    m_parserSchema.addEndTagCallback(
        TOKEN_FINGERPRINT_SHA1,
        XML_EMPTY_NAMESPACE,
        &CertificateConfigReader::tokenEndFingerprintSHA1);
}

void CertificateConfigReader::initialize(
    const std::string &file,
    const std::string &scheme)
{
    m_parserSchema.initialize(file, true, SaxReader::VALIDATION_XMLSCHEME, scheme);
}

void CertificateConfigReader::read(CertificateIdentifier &identificator)
{
    m_parserSchema.read(identificator);
}

void CertificateConfigReader::blankFunction(CertificateIdentifier &)
{
}

void CertificateConfigReader::tokenCertificateDomain(CertificateIdentifier &)
{
    std::string name = m_parserSchema.getReader().attribute(TOKEN_ATTR_NAME);

    if (name.empty()) {
        VcoreThrowMsg(CertificateConfigReader::Exception::InvalidFile,
                      "Invalid fingerprint file. Domain name is mandatory");
    } else if (name == TOKEN_VALUE_TIZEN_DEVELOPER) {
        m_certificateDomain = CertStoreId::TIZEN_DEVELOPER;
    } else if (name == TOKEN_VALUE_TIZEN_TEST) {
        m_certificateDomain = CertStoreId::TIZEN_TEST;
    } else if (name == TOKEN_VALUE_TIZEN_VERIFY) {
        m_certificateDomain = CertStoreId::TIZEN_VERIFY;
    } else if (name == TOKEN_VALUE_VISIBILITY_PUBLIC) {
        m_certificateDomain = CertStoreId::VIS_PUBLIC;
    } else if (name == TOKEN_VALUE_VISIBILITY_PARTNER) {
        m_certificateDomain = CertStoreId::VIS_PARTNER;
    } else if (name == TOKEN_VALUE_VISIBILITY_PARTNER_OPERATOR) {
        m_certificateDomain = CertStoreId::VIS_PARTNER_OPERATOR;
    } else if (name == TOKEN_VALUE_VISIBILITY_PARTNER_MANUFACTURER) {
        m_certificateDomain = CertStoreId::VIS_PARTNER_MANUFACTURER;
    } else if (name == TOKEN_VALUE_VISIBILITY_PLATFORM) {
        m_certificateDomain = CertStoreId::VIS_PLATFORM;
    } else {
        m_certificateDomain = 0;
    }
}

void CertificateConfigReader::tokenEndFingerprintSHA1(
        CertificateIdentifier &identificator)
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    std::string url = m_parserSchema.getReader().attribute(TOKEN_ATTR_URL_NAME);
#endif

    std::string text = m_parserSchema.getText();
    text += ":"; // add guard at the end of fingerprint
    Certificate::Fingerprint fingerprint;
    int s = 0;
    int byteDescLen = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (isxdigit(text[i])) {
            s <<= 4;
            s += hexCharToInt(text[i]);
            byteDescLen++;
            if (byteDescLen > 2) {
                Assert(0 && "Unsupported fingerprint format in xml file.");
            }
        } else if (text[i] == ':') {
            fingerprint.push_back(static_cast<unsigned char>(s));
            s = 0;
            byteDescLen = 0;
        } else {
            Assert(0 && "Unussported fingerprint format in xml file.");
        }
    }

    identificator.add(fingerprint, m_certificateDomain);
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    identificator.add(fingerprint, url);
#endif
}
} // namespace ValidationCore
