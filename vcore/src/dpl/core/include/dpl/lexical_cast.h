/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file    lexical_cast.h
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version 1.0
 * @brief   Header file for lexical cast
 */
#ifndef DPL_LEXICAL_CAST_H
#define DPL_LEXICAL_CAST_H

#include <sstream>

namespace VcoreDPL {
template<typename TargetType, typename SourceType>
TargetType lexical_cast(const SourceType &data)
{
    TargetType result;

    std::ostringstream out;
    out << data;

    std::istringstream in(out.str());
    in >> result;

    return result;
}
} // namespace VcoreDPL

#endif // DPL_LEXICAL_CAST_H
