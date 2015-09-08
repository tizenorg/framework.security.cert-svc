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
 * @file        CertificateConfigReader.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _VALIDATION_CORE_CERTIFICATE_CONFIG_READER_H_
#define _VALIDATION_CORE_CERTIFICATE_CONFIG_READER_H_

#include <string>

#include <vcore/CertificateIdentifier.h>
#include <vcore/CertStoreType.h>
#include <vcore/ParserSchema.h>
#include <vcore/exception.h>

namespace ValidationCore {
class CertificateConfigReader {
public:
    class Exception {
    public:
        VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base);
        VCORE_DECLARE_EXCEPTION_TYPE(Base, InvalidFile);
    };

    CertificateConfigReader();

    void initialize(const std::string &file, const std::string &scheme);
    void read(CertificateIdentifier &identificator);

private:
    void blankFunction(CertificateIdentifier &);
    void tokenCertificateDomain(CertificateIdentifier &identificator);
    void tokenEndFingerprintSHA1(CertificateIdentifier &identificator);

    CertStoreId::Type m_certificateDomain;
    ParserSchema<CertificateConfigReader, CertificateIdentifier> m_parserSchema;
};
} // namespace ValidationCore

#endif // _VALIDATION_CORE_CERTIFICATE_CONFIG_READER_H_
