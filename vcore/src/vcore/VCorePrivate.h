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
 * @file        VCore.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _VCORE_SRC_VCORE_VCOREPRIVATE_H_
#define _VCORE_SRC_VCORE_VCOREPRIVATE_H_

#include <string>
#include <VCore.h>
#include <database_checksum_vcore.h>
#include <dpl/db/thread_database_support.h>

namespace ValidationCore {
DPL::DB::ThreadDatabaseSupport& ThreadInterface(void);
} // namespace ValidationCore

#endif // _VCORE_SRC_VCORE_VCORE_H_

