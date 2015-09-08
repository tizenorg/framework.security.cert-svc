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
 * @file        orm_macros.h
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @version     1.0
 * @brief       Macro definitions for generating the SQL input file from
 * database definition.
 */

//Do not include this file directly! It is used only for SQL code generation.

#define CREATE_TABLE(name) CREATE TABLE name(
#define COLUMN(name, type, ...) name type __VA_ARGS__,
#define COLUMN_NOT_NULL(name, type, ...) name type __VA_ARGS__ not null,
#define SQL(...) __VA_ARGS__
#define TABLE_CONSTRAINTS(...) __VA_ARGS__,
#define CREATE_TABLE_END() CHECK(1) );
#define DATABASE_START(db_name)
#define DATABASE_END()

