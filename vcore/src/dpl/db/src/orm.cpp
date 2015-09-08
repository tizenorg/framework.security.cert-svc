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
 * @file        orm.cpp
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @version     1.0
 * @brief       Static definitions and function template specialziations of
 * DPL-ORM.
 */
#include <stddef.h>
#include <dpl/db/orm.h>

namespace VcoreDPL {
namespace DB {
namespace ORM {
namespace RelationTypes {
const char Equal[] = "=";
const char LessThan[] = "<";
const char And[] = "AND";
const char Or[] = "OR";
const char Is[] = "IS";
const char In[] = "IN";
}

template<>
int GetColumnFromCommand<int>(ColumnIndex columnIndex,
                              DataCommand *command)
{
    return command->GetColumnInteger(columnIndex);
}

template<>
VcoreDPL::String GetColumnFromCommand<VcoreDPL::String>(ColumnIndex columnIndex,
                                              DataCommand *command)
{
    return VcoreDPL::FromUTF8String(command->GetColumnString(columnIndex));
}

template<>
OptionalInteger GetColumnFromCommand<OptionalInteger>(ColumnIndex columnIndex,
                                                      DataCommand *command)
{
    return command->GetColumnOptionalInteger(columnIndex);
}

template<>
OptionalString GetColumnFromCommand<OptionalString>(ColumnIndex columnIndex,
                                                    DataCommand *command)
{
    return command->GetColumnOptionalString(columnIndex);
}

template<>
double GetColumnFromCommand<double>(ColumnIndex columnIndex,
                                    DataCommand *command)
{
    return command->GetColumnDouble(columnIndex);
}

void DataCommandUtils::BindArgument(DataCommand *command,
                                    ArgumentIndex index,
                                    int argument)
{
    command->BindInteger(index, argument);
}

void DataCommandUtils::BindArgument(DataCommand *command,
                                    ArgumentIndex index,
                                    const OptionalInteger& argument)
{
    command->BindInteger(index, argument);
}

void DataCommandUtils::BindArgument(DataCommand *command,
                                    ArgumentIndex index,
                                    const VcoreDPL::String& argument)
{
    command->BindString(index, argument);
}

void DataCommandUtils::BindArgument(DataCommand *command,
                                    ArgumentIndex index,
                                    const OptionalString& argument)
{
    command->BindString(index, argument);
}
}
}
}
