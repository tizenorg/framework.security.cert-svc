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
 * @file        value_separated_parser.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Parser for some value seperated files/data
 */

#ifndef VALUE_SEPARATED_PARSER_H
#define VALUE_SEPARATED_PARSER_H

#include<string>
#include<vector>
#include<memory>

#include<dpl/test/value_separated_tokens.h>
#include<dpl/test/abstract_input_parser.h>

namespace VcoreDPL {

typedef std::vector<std::string> VSLine;
typedef std::vector<VSLine> VSResult;
typedef std::shared_ptr<VSResult> VSResultPtr;

/**
 * Value Seperated parser
 *
 * Requires following policy class:
 *
 * template<VSResultPtr>
 * struct CSVParserPolicy
 * {
 *     static bool SkipLine(VSLine & );
 *     static bool Validate(VSResultPtr& result);
 * };
 */
template<class ParserPolicy>
class VSParser : public AbstractInputParser<VSResultPtr, VSToken>
{
public:
    VSParser() : m_switchLine(true), m_result(new VSResult()) {}

    void ConsumeToken(std::unique_ptr<VSToken> && token)
    {
        if(m_switchLine)
        {
            m_result->push_back(VSLine());
            m_switchLine = false;
        }
        if(token->isNewLine())
        {
            if(ParserPolicy::SkipLine(*m_result->rbegin()))
            {
                m_result->pop_back();
            }
            m_switchLine = true;
        }
        else
        {
            m_result->rbegin()->push_back(token->cell());
        }
    }

    bool IsStateValid()
    {
        return ParserPolicy::Validate(m_result);
    }

    VSResultPtr GetResult() const
    {
        return m_result;
    }

private:
    bool m_switchLine;
    VSResultPtr m_result;
};

}

#endif
