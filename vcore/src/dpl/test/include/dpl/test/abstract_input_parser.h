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
 * @file        abstract_input_parser.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Simple parser abstraction to be included into reader
 */

#ifndef ABSTRACT_INPUT_PARSER_H
#define ABSTRACT_INPUT_PARSER_H

#include <dpl/exception.h>

#include <memory>

namespace VcoreDPL {

/**
 * Abstract class of parser that produces some higher level abstraction
 * basing on incoming tokens
 */
template<class Result, class Token> class AbstractInputParser
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, ParserError)
    };

    typedef Result ResultType;
    typedef Token TokenType;

    virtual ~AbstractInputParser() {}

    virtual void ConsumeToken(std::unique_ptr<Token> && token) = 0;
    virtual bool IsStateValid() = 0;
    virtual Result GetResult() const = 0;
};

}

#endif
