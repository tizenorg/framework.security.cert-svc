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
 * @file        abstract_input_reader.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Simple output reader template
 *
 * This generic skeleton for parser which assume being composed from abstract two logical components:
 *
 *  -  parser,
 *  -  tokenizer/lexer,
 *     which implements token flow logic. Logic of components may be arbitrary. See depending change for uses.
 *
 * Components are created at start time of reader (constructor which moves arguments).
 * Virtuality (abstract base classes) are for enforcing same token type.
 * I assumed it's more clear than writen static asserts in code enforcing this.
 */

#ifndef ABSTRACT_INPUT_READER_H
#define ABSTRACT_INPUT_READER_H

#include <memory>

#include <dpl/test/abstract_input_tokenizer.h>
#include <dpl/test/abstract_input_parser.h>
#include <dpl/abstract_input.h>

namespace VcoreDPL {

/**
 * Base reader class that can be used with any AbstractInput instance
 *
 * This class is encapsulation class for tokenizer and reader subelements
 * and contains basic calculation pattern
 *
 * There a waste in form of virtuality for parser and tokenizer
 * -> this for forcing same tokenT type in both components
 */
template<class ResultT, class TokenT> class AbstractInputReader
{
public:
    typedef ResultT TokenType;
    typedef TokenT ResultType;
    typedef AbstractInputParser<ResultT, TokenT> ParserBase;
    typedef AbstractInputTokenizer<TokenT> TokenizerBase;

    class Exception
    {
    public:
        typedef typename TokenizerBase::Exception::TokenizerError TokenizerError;
        typedef typename ParserBase::Exception::ParserError ParserError;
    };

    AbstractInputReader(std::shared_ptr<AbstractInput> ia,
                        std::unique_ptr<ParserBase> && parser,
                        std::unique_ptr<TokenizerBase> && tokenizer)
        : m_parser(std::move(parser)), m_tokenizer(std::move(tokenizer))
    {
        m_tokenizer->Reset(ia);
    }

    virtual ~AbstractInputReader() {}

    ResultT ReadInput()
    {
        typedef typename Exception::TokenizerError TokenizerError;
        typedef typename Exception::ParserError ParserError;

        while(true)
        {
            std::unique_ptr<TokenT> token = m_tokenizer->GetNextToken();
            if(!token)
            {
                if(!m_tokenizer->IsStateValid())
                {
                    ThrowMsg(TokenizerError, "Tokenizer error");
                }
                if(!m_parser->IsStateValid())
                {
                    ThrowMsg(ParserError, "Parser error");
                }

                return m_parser->GetResult();
            }
            m_parser->ConsumeToken(std::move(token));
        }
    }

protected:
    std::unique_ptr<ParserBase> m_parser;
    std::unique_ptr<TokenizerBase> m_tokenizer;
};

}

#endif
