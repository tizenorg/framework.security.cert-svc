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

#ifndef _SRC_VALIDATION_CORE_VALIDATION_CORE_CONFIG_H_
#define _SRC_VALIDATION_CORE_VALIDATION_CORE_CONFIG_H_

#include <string>

#include <dpl/singleton.h>

namespace ValidationCore {
class Config {
public:
    /*
     * Set path to config file with certificate description.
     */
    bool setXMLConfigPath(const std::string& path) {
        if (!m_certificateXMLConfigPath.empty()) {
            return false;
        }
        m_certificateXMLConfigPath = path;
        return true;
    }

    /*
     * Set path to schema of config file.
     */
    bool setXMLSchemaPath(const std::string& path) {
        if (!m_certificateXMLSchemaPath.empty()) {
            return false;
        }
        m_certificateXMLSchemaPath = path;
        return true;
    }

    /*
     * Get path to config file with certificate description.
     */
    std::string getXMLConfigPath() {
        return m_certificateXMLConfigPath;
    }

    /*
     * Get path to schema of config file.
     */
    std::string getXMLSchemaPath() {
        return m_certificateXMLSchemaPath;
    }

private:
    std::string m_certificateXMLConfigPath;
    std::string m_certificateXMLSchemaPath;
};

typedef DPL::Singleton<Config> ConfigSingleton;

} // namespace ValidationCore

#endif // _SRC_VALIDATION_CORE_VALIDATION_CORE_CONFIG_H_

