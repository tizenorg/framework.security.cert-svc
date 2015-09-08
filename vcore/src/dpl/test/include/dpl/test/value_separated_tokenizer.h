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
 * @file        value_separated_tokenizer.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Tokenizer for some value seperated files/data
 */

#ifndef VALUE_SEPARATED_TOKENIZER_H
#define VALUE_SEPARATED_TOKENIZER_H

#include<dpl/test/abstract_input_tokenizer.h>
#include<dpl/test/value_separated_tokens.h>
#include<dpl/binary_queue.h>


namespace VcoreDPL {

/**
 * Value Sperated tokenizer
 *
 * Requires following policy class:
 *
 * struct TokenizerPolicy
 * {
 *     static std::string GetSeperators();
 *     static bool SkipEmpty();
 *     static void PrepareValue(std::string & value);
 * };
 */
template<class TokenizerPolicy>
class VSTokenizer : public AbstractInputTokenizer<VSToken>
{
public:
    VSTokenizer() {}

    void Reset(std::shared_ptr<AbstractInput> ia)
    {
        AbstractInputTokenizer<VSToken>::Reset(ia);
        m_queue.Clear();
        m_finished = false;
        m_newline = false;
    }

    std::unique_ptr<VSToken> GetNextToken()
    {
        std::unique_ptr<VSToken> token;
        std::string data;
        char byte;
        int tryNumber = 0;

        while(true)
        {
            //check if newline was approched
            if(m_newline)
            {
                token.reset(new VSToken());
                m_newline = false;
                return token;
            }

            //read next data
            if(m_queue.Empty())
            {
                if(m_finished)
                {
                    return token;
                }
                else
                {
                    auto baptr = m_input->Read(4096);
                    if(baptr.get() == 0)
                    {
                        ThrowMsg(Exception::TokenizerError, "Input read failed");
                    }
                    if(baptr->Empty())
                    {
                        if(TokenizerPolicy::TryAgainAtEnd(tryNumber))
                        {
                            ++tryNumber;
                            continue;
                        }
                        m_finished = true;
                        return token;
                    }
                    m_queue.AppendMoveFrom(*baptr);
                }
            }

            //process
            m_queue.FlattenConsume(&byte, 1); //queue uses pointer to consume bytes, this do not causes reallocations
            if(byte == '\n')
            {
                m_newline = true;
                if(!data.empty() || !TokenizerPolicy::SkipEmpty())
                {
                    ProduceString(token, data);
                    return token;
                }
            }
            else if(TokenizerPolicy::GetSeperators().find(byte) != std::string::npos)
            {
                if(!data.empty() || !TokenizerPolicy::SkipEmpty())
                {
                    ProduceString(token, data);
                    return token;
                }
            }
            else
            {
                data += byte;
            }
        }
    }

    bool IsStateValid()
    {
        if(!m_queue.Empty() && m_finished) return false;
        return true;
    }

protected:
    void ProduceString(std::unique_ptr<VSToken> & token, std::string & data)
    {
        TokenizerPolicy::PrepareValue(data);
        token.reset(new VSToken(data));
    }

    BinaryQueue m_queue;
    bool m_finished;
    bool m_newline;
};

}

#endif
