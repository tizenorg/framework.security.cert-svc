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
 * @file        SignatureReader.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       SignatureReader is used to parse widget digital signature.
 */
#include <vcore/SignatureReader.h>

#include <vcore/CertificateLoader.h>

namespace ValidationCore {
static const std::string XML_NAMESPACE =
    "http://www.w3.org/2000/09/xmldsig#";
static const std::string XML_NAMESPACE_DIGITALSIG =
    "http://wacapps.net/ns/digsig";
static const std::string XML_OBJ_NS =
    "http://www.w3.org/2009/xmldsig-properties";

// TAG TOKENS
static const std::string TOKEN_SIGNATURE = "Signature";
static const std::string TOKEN_SIGNED_INFO = "SignedInfo";
static const std::string TOKEN_CANONICALIZATION_METHOD =
    "CanonicalizationMethod";
static const std::string TOKEN_SIGNATURE_METHOD = "SignatureMethod";
static const std::string TOKEN_REFERENCE = "Reference";
static const std::string TOKEN_TRANSFORMS = "Transforms";
static const std::string TOKEN_TRANSFORM = "Transform";
static const std::string TOKEN_DIGEST_METHOD = "DigestMethod";
static const std::string TOKEN_DIGEST_VALUE = "DigestValue";
static const std::string TOKEN_SIGNATURE_VALUE = "SignatureValue";
static const std::string TOKEN_KEY_INFO = "KeyInfo";
static const std::string TOKEN_X509DATA = "X509Data";
static const std::string TOKEN_X509CERTIFICATE = "X509Certificate";
static const std::string TOKEN_KEY_VALUE = "KeyValue";
static const std::string TOKEN_RSA_KEY_VALUE = "RSAKeyValue";
static const std::string TOKEN_MODULUS_COMPONENT = "Modulus";
static const std::string TOKEN_EXPONENT_COMPONENT = "Exponent";
static const std::string TOKEN_ECKEY_VALUE = "ECKeyValue";
static const std::string TOKEN_NAMED_CURVE = "NamedCurve";
static const std::string TOKEN_PUBLIC_KEY = "PublicKey";
static const std::string TOKEN_OBJECT = "Object";
static const std::string TOKEN_SIGNATURE_PROPERTIES = "SignatureProperties";
static const std::string TOKEN_SIGNATURE_PROPERTY = "SignatureProperty";
static const std::string TOKEN_PROFILE = "Profile";
static const std::string TOKEN_ROLE = "Role";
static const std::string TOKEN_IDENTIFIER = "Identifier";
static const std::string TOKEN_DSAKEYVALUE = "DSAKeyValue";
static const std::string TOKEN_DSA_P_COMPONENT = "P";
static const std::string TOKEN_DSA_Q_COMPONENT = "Q";
static const std::string TOKEN_DSA_G_COMPONENT = "G";
static const std::string TOKEN_DSA_Y_COMPONENT = "Y";
static const std::string TOKEN_DSA_J_COMPONENT = "J";
static const std::string TOKEN_DSA_SEED_COMPONENT = "Seed";
static const std::string TOKEN_DSA_PGENCOUNTER_COMPONENT = "PgenCounter";
static const std::string TOKEN_TARGET_RESTRICTION = "TargetRestriction";

// ATTRIBUTTE TOKENS

static const std::string TOKEN_ALGORITHM = "Algorithm";
static const std::string TOKEN_URI = "URI";
static const std::string TOKEN_ID = "Id";
static const std::string TOKEN_TARGET = "Target";
static const std::string TOKEN_IMEI = "IMEI";
static const std::string TOKEN_MEID = "MEID";

// ATTIRUBTE VALUES

static const std::string TOKEN_ATTR_PROFILE = "profile";
static const std::string TOKEN_ATTR_ROLE = "role";
static const std::string TOKEN_ATTR_IDENTIFIER = "identifier";

// ALGORITHMS

//static const std::string TOKEN_ALGORITHM_XML_EXC_CAN   =
//            "http://www.w3.org/2001/10/xml-exc-c14n#";
//static const std::string TOKEN_ALGORITHM_RSA_SHA256    =
//            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
//static const std::string TOKEN_ALGORITHM_DSA_SHA1      =
//            "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
//static const std::string TOKEN_ALGORITHM_ECDSA_SHA256  =
//            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
//static const std::string TOKEN_ALGORITHM_SHA1          =
//            "http://www.w3.org/2000/09/xmldsig#sha1";
//static const std::string TOKEN_ALGORITHM_SHA256        =
//            "http://www.w3.org/2001/04/xmlenc#sha256";
//static const std::string TOKEN_ALGORITHM_SHA384        =
//            "http://www.w3.org/2001/04/xmldsig-more#sha384";
//static const std::string TOKEN_ALGORITHM_SHA512        =
//            "http://www.w3.org/2001/04/xmlenc#sha512";

SignatureReader::SignatureReader() :
    m_signaturePropertiesCounter(0),
    m_targetRestrictionObjectFound(false),
    m_parserSchema(this)
{
    /**
     * member func pointers map
     */
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNATURE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNED_INFO,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_CANONICALIZATION_METHOD,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNATURE_METHOD,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_REFERENCE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_TRANSFORMS,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_TRANSFORM,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DIGEST_METHOD,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DIGEST_VALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNATURE_VALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_KEY_INFO,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenKeyInfo);
    m_parserSchema.addBeginTagCallback(TOKEN_X509DATA,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenX509Data);
    m_parserSchema.addBeginTagCallback(TOKEN_X509CERTIFICATE,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenX509Certificate);
    m_parserSchema.addBeginTagCallback(TOKEN_ECKEY_VALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_NAMED_CURVE,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenNamedCurve);
    m_parserSchema.addBeginTagCallback(TOKEN_PUBLIC_KEY,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenPublicKey);
    m_parserSchema.addBeginTagCallback(TOKEN_OBJECT,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenObject);
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNATURE_PROPERTIES,
                                       XML_NAMESPACE,
                                       &SignatureReader::tokenSignatureProperties);
    m_parserSchema.addBeginTagCallback(TOKEN_SIGNATURE_PROPERTY,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_PROFILE,
                                       XML_OBJ_NS,
                                       &SignatureReader::tokenProfile);
    m_parserSchema.addBeginTagCallback(TOKEN_ROLE,
                                       XML_OBJ_NS,
                                       &SignatureReader::tokenRole);
    m_parserSchema.addBeginTagCallback(TOKEN_IDENTIFIER,
                                       XML_OBJ_NS,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_KEY_VALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSAKEYVALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_P_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_Q_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_G_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_Y_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_J_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_SEED_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_DSA_PGENCOUNTER_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_RSA_KEY_VALUE,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_MODULUS_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_EXPONENT_COMPONENT,
                                       XML_NAMESPACE,
                                       &SignatureReader::blankFunction);
    m_parserSchema.addBeginTagCallback(TOKEN_TARGET_RESTRICTION,
                                       XML_NAMESPACE_DIGITALSIG,
                                       &SignatureReader::tokenTargetRestriction);

    m_parserSchema.addEndTagCallback(TOKEN_SIGNATURE,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_SIGNED_INFO,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_CANONICALIZATION_METHOD,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_SIGNATURE_METHOD,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_REFERENCE,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_TRANSFORMS,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_TRANSFORM,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_DIGEST_METHOD,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_DIGEST_VALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_SIGNATURE_VALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_KEY_INFO,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndKeyInfo);
    m_parserSchema.addEndTagCallback(TOKEN_X509DATA,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndX509Data);
    m_parserSchema.addEndTagCallback(TOKEN_X509CERTIFICATE,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndX509Certificate);
    m_parserSchema.addEndTagCallback(TOKEN_ECKEY_VALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndECKeyValue);
    m_parserSchema.addEndTagCallback(TOKEN_PUBLIC_KEY,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndPublicKey);
    m_parserSchema.addEndTagCallback(TOKEN_OBJECT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndObject);
    m_parserSchema.addEndTagCallback(TOKEN_SIGNATURE_PROPERTIES,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_SIGNATURE_PROPERTY,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_PROFILE,
                                     XML_OBJ_NS,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_ROLE,
                                     XML_OBJ_NS,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_IDENTIFIER,
                                     XML_OBJ_NS,
                                     &SignatureReader::tokenEndIdentifier);
    m_parserSchema.addEndTagCallback(TOKEN_KEY_VALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
    m_parserSchema.addEndTagCallback(TOKEN_DSAKEYVALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAKeyValue);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_P_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAPComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_Q_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAQComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_G_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAGComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_Y_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAYComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_J_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAJComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_SEED_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSASeedComponent);
    m_parserSchema.addEndTagCallback(TOKEN_DSA_PGENCOUNTER_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndDSAPGenCounterComponent);
    m_parserSchema.addEndTagCallback(TOKEN_RSA_KEY_VALUE,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndRSAKeyValue);
    m_parserSchema.addEndTagCallback(TOKEN_MODULUS_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndKeyModulus);
    m_parserSchema.addEndTagCallback(TOKEN_EXPONENT_COMPONENT,
                                     XML_NAMESPACE,
                                     &SignatureReader::tokenEndKeyExponent);
    m_parserSchema.addEndTagCallback(TOKEN_TARGET_RESTRICTION,
                                     XML_NAMESPACE,
                                     &SignatureReader::blankFunction);
}


void SignatureReader::initialize(
    SignatureData &signatureData,
    const std::string &xmlscheme)
{
    m_parserSchema.initialize(
            signatureData.getSignatureFileName(),
            true,
            SaxReader::VALIDATION_XMLSCHEME,
            xmlscheme);
}

void SignatureReader::read(SignatureData &signatureData)
{
    m_parserSchema.read(signatureData);
}

void SignatureReader::blankFunction(SignatureData &)
{
}

void SignatureReader::tokenKeyInfo(SignatureData &)
{
}

void SignatureReader::tokenX509Data(SignatureData &)
{
}

void SignatureReader::tokenX509Certificate(SignatureData &)
{
}

void SignatureReader::tokenPublicKey(SignatureData &)
{
}

void SignatureReader::tokenNamedCurve(SignatureData &)
{
    m_nameCurveURI = m_parserSchema.getReader().attribute(TOKEN_URI);
}

void SignatureReader::tokenTargetRestriction(SignatureData &signatureData)
{
    std::string IMEI = m_parserSchema.getReader().attribute(TOKEN_IMEI);
    std::string MEID = m_parserSchema.getReader().attribute(TOKEN_MEID);

    //less verbose way to say (IMEI && MEID) || (!IMEI && !MEID)
    if (IMEI.empty() == MEID.empty()) {
        //WAC 2.0 WR-4650 point 4
        VcoreThrowMsg(SignatureReader::Exception::TargetRestriction,
                      "TargetRestriction should contain exactly one attribute.");
    }

    if (!IMEI.empty()) {
        signatureData.m_imeiList.push_back(IMEI);
    }
    if (!MEID.empty()) {
        signatureData.m_meidList.push_back(MEID);
    }
}

void SignatureReader::tokenEndKeyInfo(SignatureData &)
{
}

void SignatureReader::tokenEndX509Data(SignatureData &)
{
}

void SignatureReader::tokenEndX509Certificate(SignatureData &signatureData)
{
    CertificateLoader loader;
    if (CertificateLoader::NO_ERROR !=
        loader.loadCertificateFromRawData(m_parserSchema.getText())) {
        fprintf(stderr, "## [validate error]: Certificate could not be loaded\n");
        VcoreThrowMsg(ParserSchemaException::CertificateLoaderError,
                      "Certificate could not be loaded");
    }
    signatureData.m_certList.push_back(loader.getCertificatePtr());
}

void SignatureReader::tokenEndRSAKeyValue(SignatureData &signatureData)
{
    CertificateLoader loader;
    if (CertificateLoader::NO_ERROR !=
        loader.loadCertificateBasedOnExponentAndModulus(m_modulus,
                                                        m_exponent)) {
        fprintf(stderr, "## [validate error]: Certificate could not be loaded\n");
        VcoreThrowMsg(ParserSchemaException::CertificateLoaderError,
                      "Certificate could not be loaded");
    }
    signatureData.m_certList.push_back(loader.getCertificatePtr());
}

void SignatureReader::tokenEndKeyModulus(SignatureData &)
{
    m_modulus = m_parserSchema.getText();
}

void SignatureReader::tokenEndKeyExponent(SignatureData &)
{
    m_exponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndPublicKey(SignatureData &)
{
    m_publicKey = m_parserSchema.getText();
}

void SignatureReader::tokenEndECKeyValue(SignatureData &signatureData)
{
    CertificateLoader loader;
    if (CertificateLoader::NO_ERROR !=
        loader.loadCertificateWithECKEY(m_nameCurveURI, m_publicKey)) {
        fprintf(stderr, "## [validate error]: Certificate could not be loaded\n");
        VcoreThrowMsg(ParserSchemaException::CertificateLoaderError,
                      "Certificate could not be loaded");
    }
    signatureData.m_certList.push_back(loader.getCertificatePtr());
}

void SignatureReader::tokenEndObject(SignatureData &signatureData)
{
    m_signaturePropertiesCounter = 0;

    if (((!signatureData.m_imeiList.empty()) ||
         (!signatureData.m_meidList.empty())) &&
        m_targetRestrictionObjectFound) {
        //WAC 2.0 WR-4650 point 1
        VcoreThrowMsg(SignatureReader::Exception::TargetRestriction,
                      "TargetRestriction should contain exactly one ds:Object "
                      "containing zero or more wac:TargetRestriction children.");
    }

    if ((!signatureData.m_imeiList.empty()) ||
        (!signatureData.m_meidList.empty())) {
        m_targetRestrictionObjectFound = true;
    }

}
void SignatureReader::tokenEndDSAPComponent(SignatureData &)
{
    m_dsaKeyPComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAQComponent(SignatureData &)
{
    m_dsaKeyQComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAGComponent(SignatureData &)
{
    m_dsaKeyGComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAYComponent(SignatureData &)
{
    m_dsaKeyYComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAJComponent(SignatureData &)
{
    m_dsaKeyJComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSASeedComponent(SignatureData &)
{
    m_dsaKeySeedComponent = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAPGenCounterComponent(SignatureData &)
{
    m_dsaKeyPGenCounter = m_parserSchema.getText();
}

void SignatureReader::tokenEndDSAKeyValue(SignatureData &signatureData)
{
    CertificateLoader loader;

    if (CertificateLoader::NO_ERROR !=
        loader.loadCertificateBasedOnDSAComponents(m_dsaKeyPComponent,
                                                   m_dsaKeyQComponent,
                                                   m_dsaKeyGComponent,
                                                   m_dsaKeyYComponent,
                                                   m_dsaKeyJComponent,
                                                   m_dsaKeySeedComponent,
                                                   m_dsaKeyPGenCounter)) {
        fprintf(stderr, "## [validate error]: Certificate could not be loaded\n");
        VcoreThrowMsg(ParserSchemaException::CertificateLoaderError,
                      "Certificate could not be loaded.");
    }
    signatureData.m_certList.push_back(loader.getCertificatePtr());
}

void SignatureReader::tokenRole(SignatureData &signatureData)
{
    if (!signatureData.m_roleURI.empty()) {
        fprintf(stderr, "## [validate error]: Multiple definition of Role is not allowed\n");
        VcoreThrowMsg(ParserSchemaException::UnsupportedValue,
                      "Multiple definition of Role is not allowed.");
    }
    signatureData.m_roleURI = m_parserSchema.getReader().attribute(TOKEN_URI);
}

void SignatureReader::tokenProfile(SignatureData &signatureData)
{
    if (!signatureData.m_profileURI.empty()) {
        fprintf(stderr, "## [validate error]: Multiple definition of Profile is not allowed\n");
        VcoreThrowMsg(ParserSchemaException::UnsupportedValue,
                      "Multiple definition of Profile is not allowed.");
    }
    signatureData.m_profileURI = m_parserSchema.getReader().attribute(TOKEN_URI);
}

void SignatureReader::tokenEndIdentifier(SignatureData &signatureData)
{
    if (!signatureData.m_identifier.empty()) {
        fprintf(stderr, "## [validate error]: Multiple definition of Identifier is not allowed\n");
        VcoreThrowMsg(ParserSchemaException::UnsupportedValue,
                      "Multiple definition of Identifier is not allowed.");
    }
    signatureData.m_identifier = m_parserSchema.getText();
}

void SignatureReader::tokenObject(SignatureData &signatureData)
{
    std::string id = m_parserSchema.getReader().attribute(TOKEN_ID);

    if (id.empty()) {
        fprintf(stderr, "## [validate error]: Unsupported value of Attribute Id in Object tag\n");
        VcoreThrowMsg(ParserSchemaException::UnsupportedValue,
                      "Unsupported value of Attribute Id in Object tag.");
    }

    signatureData.m_objectList.push_back(id);
}

void SignatureReader::tokenSignatureProperties(SignatureData &)
{
    if (++m_signaturePropertiesCounter > 1) {
        fprintf(stderr, "## [validate error]: Only one SignatureProperties tag is allowed in Object\n");
        VcoreThrowMsg(ParserSchemaException::UnsupportedValue,
                      "Only one SignatureProperties tag is allowed in Object");
    }
}
} // namespace ValidationCore
