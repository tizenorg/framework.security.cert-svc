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
 * @file        value_separated_policies.h
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       Example policy classes for some value seperated files/data
 */

#ifndef VALUE_SEPARATED_POLICIES_H
#define VALUE_SEPARATED_POLICIES_H

#include<string>
#include<vector>
#include<memory>

namespace VcoreDPL {

struct CSVTokenizerPolicy
{
    static std::string GetSeperators();      //cells in line are separated by given characters
    static bool SkipEmpty();                 //if cell is empty, shoudl I skip?
    static void PrepareValue(std::string &); //transform each value
    static bool TryAgainAtEnd(int);          //read is nonblocking so dat may not be yet available, should I retry?
};

struct CSVParserPolicy
{
    static bool SkipLine(const std::vector<std::string> & );                                  //should I skip whole readline?
    static bool Validate(std::shared_ptr<std::vector<std::vector<std::string> > > & result);  //validate and adjust output data
};

}

#endif
