/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        value_separated_tokens.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Token class for some value seperated files/data
 */

#ifndef VALUE_SEPARATED_TOKENS_H
#define VALUE_SEPARATED_TOKENS_H

#include<string>

namespace VcoreDPL {

class VSToken
{
public:
    VSToken(const std::string & c);
    VSToken(); //newline token - no new class to simplify
    const std::string & cell() const;

    bool isNewLine();
private:
    bool m_newline;
    std::string m_cell;
};

}

#endif
