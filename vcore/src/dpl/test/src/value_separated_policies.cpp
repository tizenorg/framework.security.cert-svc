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
 * @file        value_separated_policies.cpp
 * @author      Tomasz Iwanek (t.iwanek@samsung.com)
 * @brief       ...
 */

#include<dpl/test/value_separated_policies.h>
#include<dpl/foreach.h>
#include<dpl/log/vcore_log.h>

namespace VcoreDPL {

std::string CSVTokenizerPolicy::GetSeperators()
{
    return ",";
}

bool CSVTokenizerPolicy::SkipEmpty()
{
    return false;
}

void CSVTokenizerPolicy::PrepareValue(std::string &)
{
}

bool CSVTokenizerPolicy::TryAgainAtEnd(int)
{
    return false;
}

bool CSVParserPolicy::SkipLine(const std::vector<std::string> & )
{
    return false;
}

bool CSVParserPolicy::Validate(std::shared_ptr<std::vector<std::vector<std::string> > > & result)
{
    int num = -1;
    FOREACH(r, *result)
    {
        int size = r->size();
        if(num != -1 && num != size)
        {
            VcoreLogE("Columns not matches");
            return false;
        }
        num = size;
    }
    return true;
}

}
