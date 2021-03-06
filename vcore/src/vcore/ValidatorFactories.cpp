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
#include <vcore/ValidatorFactories.h>

#include <string>
#include <dpl/log/log.h>

#include <vcore/Certificate.h>
#include <vcore/CertificateConfigReader.h>
#include <vcore/Config.h>

namespace ValidationCore {

const CertificateIdentifier& createCertificateIdentifier()
{
    static CertificateIdentifier certificateIdentifier;
    static bool initialized = false;
    if (!initialized) {
        CertificateConfigReader reader;
        std::string file =
            ConfigSingleton::Instance().getXMLConfigPath();
        LogDebug("File with fingerprint list is: " << file);
        std::string schema =
            ConfigSingleton::Instance().getXMLSchemaPath();
        LogDebug("File with fingerprint list schema is: " << schema);
        reader.initialize(file, schema);
        reader.read(certificateIdentifier);
        initialized = true;
    }
    return certificateIdentifier;
}

} // namespace ValidationCore
