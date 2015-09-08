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
 * @file        value_separated_tokens.cpp
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       ...
 */

#include <dpl/test/value_separated_tokens.h>

namespace VcoreDPL {

VSToken::VSToken(const std::string & c) :  m_newline(false), m_cell(c)
{
}

VSToken::VSToken() : m_newline(true)
{
}

const std::string & VSToken::cell() const
{
    return m_cell;
}

bool VSToken::isNewLine()
{
    return m_newline;
}

}
