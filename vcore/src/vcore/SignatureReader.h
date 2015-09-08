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
 * @file        SignatureReader.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       SignatureReader is used to parse widget digital signature.
 */
#ifndef _VALIDATION_CORE_SIGNATUREREADER_H_
#define _VALIDATION_CORE_SIGNATUREREADER_H_

#include <vcore/SignatureData.h>
#include <vcore/ParserSchema.h>
#include <vcore/exception.h>

#include <map>

namespace ValidationCore {

class SignatureReader {
public:
    class Exception {
    public:
        VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base);
        VCORE_DECLARE_EXCEPTION_TYPE(Base, TargetRestriction);
    };

    SignatureReader();

    void initialize(SignatureData &signatureData, const std::string &xmlscheme);

    void read(SignatureData &signatureData);

private:
    void blankFunction(SignatureData &signatureData);

    void tokenKeyInfo(SignatureData &signatureData);
    void tokenKeyModulus(SignatureData &signatureData);
    void tokenKeyExponent(SignatureData &signatureData);
    void tokenX509Data(SignatureData &signatureData);
    void tokenX509Certificate(SignatureData &signatureData);
    void tokenPublicKey(SignatureData &signatureData);
    void tokenNamedCurve(SignatureData &signatureData);
    void tokenRole(SignatureData &signatureData);
    void tokenProfile(SignatureData &signatureData);
    void tokenObject(SignatureData &signatureData);
    void tokenSignatureProperties(SignatureData &signatureData);

    void tokenTargetRestriction(SignatureData &signatureData);

    void tokenEndKeyInfo(SignatureData &signatureData);
    // KW     void tokenEndKeyName(SignatureData &signatureData);

    void tokenEndRSAKeyValue(SignatureData &signatureData);

    void tokenEndKeyModulus(SignatureData &signatureData);
    void tokenEndKeyExponent(SignatureData &signatureData);
    void tokenEndX509Data(SignatureData &signatureData);

    void tokenEndX509Certificate(SignatureData &signatureData);

    void tokenEndPublicKey(SignatureData &signatureData);
    void tokenEndECKeyValue(SignatureData &signatureData);
    void tokenEndIdentifier(SignatureData &signatureData);
    void tokenEndObject(SignatureData &signatureData);

    // DSA key components
    void tokenEndDSAPComponent(SignatureData& signatureData);
    void tokenEndDSAQComponent(SignatureData& signatureData);
    void tokenEndDSAGComponent(SignatureData& signatureData);
    void tokenEndDSAYComponent(SignatureData& signatureData);
    void tokenEndDSAJComponent(SignatureData& signatureData);

    void tokenEndDSAKeyValue(SignatureData& signatureData);

    void tokenEndDSASeedComponent(SignatureData& signatureData);
    void tokenEndDSAPGenCounterComponent(SignatureData& signatureData);

    // temporary values required due reference parsing process
    // optional parameters for dsa
    std::string m_dsaKeyPComponent;
    std::string m_dsaKeyQComponent;
    std::string m_dsaKeyGComponent;
    std::string m_dsaKeyYComponent;
    std::string m_dsaKeyJComponent;
    std::string m_dsaKeySeedComponent;
    std::string m_dsaKeyPGenCounter;
    // temporary values of ecdsa key
    std::string m_publicKey;
    std::string m_nameCurveURI;
    std::string m_modulus;
    std::string m_exponent;

    // temporary values required due Object parsing
    int m_signaturePropertiesCounter;
    bool m_targetRestrictionObjectFound;

    ParserSchema<SignatureReader, SignatureData> m_parserSchema;
};
}

#endif // _VALIDATION_CORE_SIGNATUREREADER_H_
