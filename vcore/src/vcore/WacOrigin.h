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
 * @brief       This is stub for HTML5Origin implementation.
 *              This implementation is compatible with WAC 2.0 PRV requirements
 *              and is _not_ full compatible with ORIGIN algorithm requirements
 *              defined in http://www.w3.org/TR/html5/origin-0.html#origin-0
 */
#ifndef _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_HTML5ORIGIN_H_
#define _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_HTML5ORIGIN_H_

#include <string>

namespace ValidationCore {
class WacOrigin
{
  public:

    WacOrigin(const std::string &url);
    WacOrigin(const char *url);

    bool operator!=(const WacOrigin &second) const
    {
        return !(operator==(second));
    }

    bool operator==(const WacOrigin &second) const;

  private:
    void parse(const char *url);
    void setPort();

    std::string m_scheme;
    std::string m_host;
    int m_port;
    bool m_parseFailed; // if parsing failed we should return unique identifier
};
} //namespace ValidationCore

#endif // _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_HTML5ORIGIN_H_
