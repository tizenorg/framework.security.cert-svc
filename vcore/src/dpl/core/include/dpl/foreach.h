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
 * @file        foreach.h
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of foreach macro for stl
 * containers
 */
#ifndef DPL_FOREACH_H
#define DPL_FOREACH_H

#include <dpl/preprocessor.h>

namespace VcoreDPL {
namespace Private {
/*
 * Used to detect type of valid reference to value object.
 */
template <typename T>
T& ValueReference(T& t)
{
    return(t);
}

template <typename T>
const T& ValueReference(const T& t)
{
    return(t);
}
} //Private
} //DPL

#define DPL_FOREACH_IMPL(temporaryName, iterator, container)            \
    __typeof__ (VcoreDPL::Private::ValueReference((container))) &            \
    temporaryName = (container);                                        \
    for (__typeof__ (temporaryName.begin())iterator =                  \
             temporaryName.begin();                                     \
         (iterator) != temporaryName.end(); ++iterator)

#define FOREACH(iterator, container)                                    \
    DPL_FOREACH_IMPL(                                                   \
        DPL_MACRO_CONCAT(foreachContainerReference, __COUNTER__),       \
        iterator,                                      \
        container)

#endif // DPL_FOREACH_H
