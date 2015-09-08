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
 * @file        preprocessor.h
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This file contains some usefull macros.
 */

#ifndef DPL_PREPROCESSOR_H
#define DPL_PREPROCESSOR_H

#define DPL_MACRO_CONCAT_IMPL(x, y) x##y
#define DPL_MACRO_CONCAT(x, y) DPL_MACRO_CONCAT_IMPL(x, y)

#ifdef __COUNTER__
#define DPL_ANONYMOUS_VARIABLE(name) DPL_MACRO_CONCAT(name, __COUNTER__)
#else
#define DPL_ANONYMOUS_VARIABLE(name) DPL_MACRO_CONCAT(name, __LINE__)
#endif

#endif //DPL_PREPROCESSOR_H
