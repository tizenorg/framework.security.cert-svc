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
 * @file        abstract_input_tokenizer.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Simple tokenizer abstraction
 */

#ifndef ABSTRACT_INPUT_TOKENIZER_H
#define ABSTRACT_INPUT_TOKENIZER_H

#include <memory>
#include <string>

#include <dpl/abstract_input.h>
#include <dpl/exception.h>

namespace VcoreDPL {

/**
 * Tokenizer abstract base class
 *
 * This class is supposed to accept AbstractInput in constructor
 * and produce tokens until end of source. If parsing ends in invalid state
 * then IsStateValid() should return false
 */
template<class Token> class AbstractInputTokenizer
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, TokenizerError)
    };

    typedef Token TokenType;

    AbstractInputTokenizer() {}
    virtual ~AbstractInputTokenizer() {}

    /**
     * @brief Reset resets data source
     * @param wia AbstractWaitableInputAdapter instance
     */
    virtual void Reset(std::shared_ptr<AbstractInput> wia)
    {
        m_input = wia;
    }

    /**
     * @brief GetNextToken
     *
     * Parses next token.
     * Returns pointer to token
     * @throw TokenizerError in condition of input source error
     * If returned empty pointer IsStateValid() == true -> end of input
     *                           IsStateValid() == false -> error
     *
     * @param token token to be set
     * @return
     */
    virtual std::unique_ptr<Token> GetNextToken() = 0;
    virtual bool IsStateValid() = 0;

protected:
    std::shared_ptr<AbstractInput> m_input;
};

}

#endif
