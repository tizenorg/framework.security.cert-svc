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
 * @file        value_separated_reader.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Reader for some value seperated files/data
 *
 * This is parser for files containing lines with values seperated with custom charaters.
 * Purpose of this is to parse output similar to csv and hide (no need for rewriting)
 * buffers, reads, code errors. Result is two dimensional array.
 *
 * Reader is designed as class configured with policies classes:
 *  http://en.wikipedia.org/wiki/Policy-based_design
 */

#ifndef VALUE_SEPARATED_READER_H
#define VALUE_SEPARATED_READER_H

#include<dpl/test/abstract_input_reader.h>
#include<dpl/test/value_separated_tokenizer.h>
#include<dpl/test/value_separated_parser.h>
#include<dpl/test/value_separated_tokens.h>
#include<dpl/test/value_separated_policies.h>

namespace VcoreDPL {

/**
 * Reader for input with values separated with defined characters
 *
 * Usage:
 * - define both policies classes for defining and customize exact behaviour of reader
 * - make typedef for VSReader template instance with your policies
 *
 */
template<class ParserPolicy, class TokenizerPolicy>
class VSReader : public AbstractInputReader<VSResultPtr, VSToken>
{
public:
    VSReader(std::shared_ptr<AbstractInput> wia)
        : AbstractInputReader<VSResultPtr, VSToken>(wia,
                std::unique_ptr<ParserBase>(new VSParser<ParserPolicy>()),
                std::unique_ptr<TokenizerBase>(new VSTokenizer<TokenizerPolicy>()))
    {}
};

typedef VSReader<CSVParserPolicy, CSVTokenizerPolicy> CSVReader;

}

#endif
