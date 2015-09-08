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
 * @file    orm_interface.h
 * @author  Lukasz Marek (l.marek@samsung.com)
 * @version 1.0
 */

#include <string>
#include <dpl/db/sql_connection.h>

#ifndef DPL_ORM_INTERFACE_H
#define DPL_ORM_INTERFACE_H

namespace VcoreDPL {
namespace DB {
namespace ORM {
class IOrmInterface
{
  public:
    virtual ~IOrmInterface() {}
    virtual VcoreDPL::DB::SqlConnection::DataCommand *AllocDataCommand(
        const std::string &statement) = 0;
    virtual void FreeDataCommand(VcoreDPL::DB::SqlConnection::DataCommand *command)
        = 0;
    virtual void TransactionBegin() = 0;
    virtual void TransactionCommit() = 0;
    virtual void TransactionRollback() = 0;
    virtual VcoreDPL::DB::SqlConnection::RowID GetLastInsertRowID() = 0;
};
}
}
}

#endif
