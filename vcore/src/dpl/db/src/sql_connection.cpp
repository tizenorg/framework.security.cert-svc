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
 * @file        sql_connection.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL connection
 */
#include <stddef.h>
#include <dpl/db/sql_connection.h>
#include <dpl/db/naive_synchronization_object.h>
#include <dpl/free_deleter.h>
#include <memory>
#include <dpl/noncopyable.h>
#include <dpl/assert.h>
#include <unistd.h>
#include <cstdio>
#include <cstdarg>

namespace VcoreDPL {
namespace DB {
namespace // anonymous
{
class ScopedNotifyAll :
    public Noncopyable
{
  private:
    SqlConnection::SynchronizationObject *m_synchronizationObject;

  public:
    explicit ScopedNotifyAll(
        SqlConnection::SynchronizationObject *synchronizationObject) :
        m_synchronizationObject(synchronizationObject)
    {}

    ~ScopedNotifyAll()
    {
        if (!m_synchronizationObject) {
            return;
        }

        VcoreLogD("Notifying after successful synchronize");
        m_synchronizationObject->NotifyAll();
    }
};
} // namespace anonymous

SqlConnection::DataCommand::DataCommand(SqlConnection *connection,
                                        const char *buffer) :
    m_masterConnection(connection),
    m_stmt(NULL)
{
    Assert(connection != NULL);

    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(connection->m_synchronizationObject.get());

    for (;;) {
        int ret = sqlite3_prepare_v2(connection->m_connection,
                                     buffer, strlen(buffer),
                                     &m_stmt, NULL);

        if (ret == SQLITE_OK) {
            VcoreLogD("Data command prepared successfuly");
            break;
        } else if (ret == SQLITE_BUSY) {
            VcoreLogD("Collision occurred while preparing SQL command");

            // Synchronize if synchronization object is available
            if (connection->m_synchronizationObject) {
                VcoreLogD("Performing synchronization");
                connection->m_synchronizationObject->Synchronize();
                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        const char *error = sqlite3_errmsg(m_masterConnection->m_connection);

        VcoreLogD("SQL prepare data command failed");
        VcoreLogD("    Statement: %s", buffer);
        VcoreLogD("    Error: %s", error);

        ThrowMsg(Exception::SyntaxError, error);
    }

    VcoreLogD("Prepared data command: %s", buffer);

    // Increment stored data command count
    ++m_masterConnection->m_dataCommandsCount;
}

SqlConnection::DataCommand::~DataCommand()
{
    VcoreLogD("SQL data command finalizing");

    if (sqlite3_finalize(m_stmt) != SQLITE_OK) {
        VcoreLogD("Failed to finalize data command");
    }

    // Decrement stored data command count
    --m_masterConnection->m_dataCommandsCount;
}

void SqlConnection::DataCommand::CheckBindResult(int result)
{
    if (result != SQLITE_OK) {
        const char *error = sqlite3_errmsg(
                m_masterConnection->m_connection);

        VcoreLogD("Failed to bind SQL statement parameter");
        VcoreLogD("    Error: %s", error);

        ThrowMsg(Exception::SyntaxError, error);
    }
}

void SqlConnection::DataCommand::BindNull(
    SqlConnection::ArgumentIndex position)
{
    CheckBindResult(sqlite3_bind_null(m_stmt, position));
    VcoreLogD("SQL data command bind null: [%i]", position);
}

void SqlConnection::DataCommand::BindInteger(
    SqlConnection::ArgumentIndex position,
    int value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position, value));
    VcoreLogD("SQL data command bind integer: [%i] -> %i", position, value);
}

void SqlConnection::DataCommand::BindInt8(
    SqlConnection::ArgumentIndex position,
    int8_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    VcoreLogD("SQL data command bind int8: [%i] -> %i", position, value);
}

void SqlConnection::DataCommand::BindInt16(
    SqlConnection::ArgumentIndex position,
    int16_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    VcoreLogD("SQL data command bind int16: [%i] -> %i", position, value);
}

void SqlConnection::DataCommand::BindInt32(
    SqlConnection::ArgumentIndex position,
    int32_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    VcoreLogD("SQL data command bind int32: [%i] -> %i", position, value);
}

void SqlConnection::DataCommand::BindInt64(
    SqlConnection::ArgumentIndex position,
    int64_t value)
{
    CheckBindResult(sqlite3_bind_int64(m_stmt, position,
                                       static_cast<sqlite3_int64>(value)));
    VcoreLogD("SQL data command bind int64: [%i] -> %lli", position, value);
}

void SqlConnection::DataCommand::BindFloat(
    SqlConnection::ArgumentIndex position,
    float value)
{
    CheckBindResult(sqlite3_bind_double(m_stmt, position,
                                        static_cast<double>(value)));
    VcoreLogD("SQL data command bind float: [%i] -> %f", position, value);
}

void SqlConnection::DataCommand::BindDouble(
    SqlConnection::ArgumentIndex position,
    double value)
{
    CheckBindResult(sqlite3_bind_double(m_stmt, position, value));
    VcoreLogD("SQL data command bind double: [%i] -> %f", position, value);
}

void SqlConnection::DataCommand::BindString(
    SqlConnection::ArgumentIndex position,
    const char *value)
{
    if (!value) {
        BindNull(position);
        return;
    }

    // Assume that text may disappear
    CheckBindResult(sqlite3_bind_text(m_stmt, position,
                                      value, strlen(value),
                                      SQLITE_TRANSIENT));

    VcoreLogD("SQL data command bind string: [%i] -> %s", position, value);
}

void SqlConnection::DataCommand::BindString(
    SqlConnection::ArgumentIndex position,
    const String &value)
{
    BindString(position, ToUTF8String(value).c_str());
}

void SqlConnection::DataCommand::BindInteger(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInteger(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt8(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int8_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt8(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt16(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int16_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt16(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt32(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int32_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt32(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt64(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int64_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt64(position, *value);
    }
}

void SqlConnection::DataCommand::BindFloat(
    SqlConnection::ArgumentIndex position,
    const boost::optional<float> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindFloat(position, *value);
    }
}

void SqlConnection::DataCommand::BindDouble(
    SqlConnection::ArgumentIndex position,
    const boost::optional<double> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindDouble(position, *value);
    }
}

void SqlConnection::DataCommand::BindString(
    SqlConnection::ArgumentIndex position,
    const boost::optional<String> &value)
{
    if (!!value) {
        BindString(position, ToUTF8String(*value).c_str());
    } else {
        BindNull(position);
    }
}

bool SqlConnection::DataCommand::Step()
{
    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(
        m_masterConnection->m_synchronizationObject.get());

    for (;;) {
        int ret = sqlite3_step(m_stmt);

        if (ret == SQLITE_ROW) {
            VcoreLogD("SQL data command step ROW");
            return true;
        } else if (ret == SQLITE_DONE) {
            VcoreLogD("SQL data command step DONE");
            return false;
        } else if (ret == SQLITE_BUSY) {
            VcoreLogD("Collision occurred while executing SQL command");

            // Synchronize if synchronization object is available
            if (m_masterConnection->m_synchronizationObject) {
                VcoreLogD("Performing synchronization");

                m_masterConnection->
                    m_synchronizationObject->Synchronize();

                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        const char *error = sqlite3_errmsg(m_masterConnection->m_connection);

        VcoreLogD("SQL step data command failed");
        VcoreLogD("    Error: %s", error);

        ThrowMsg(Exception::InternalError, error);
    }
}

void SqlConnection::DataCommand::Reset()
{
    /*
     * According to:
     * http://www.sqlite.org/c3ref/stmt.html
     *
     * if last sqlite3_step command on this stmt returned an error,
     * then sqlite3_reset will return that error, althought it is not an error.
     * So sqlite3_reset allways succedes.
     */
    sqlite3_reset(m_stmt);

    VcoreLogD("SQL data command reset");
}

void SqlConnection::DataCommand::CheckColumnIndex(
    SqlConnection::ColumnIndex column)
{
    if (column < 0 || column >= sqlite3_column_count(m_stmt)) {
        ThrowMsg(Exception::InvalidColumn, "Column index is out of bounds");
    }
}

bool SqlConnection::DataCommand::IsColumnNull(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column type: [%i]", column);
    CheckColumnIndex(column);
    return sqlite3_column_type(m_stmt, column) == SQLITE_NULL;
}

int SqlConnection::DataCommand::GetColumnInteger(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column integer: [%i]", column);
    CheckColumnIndex(column);
    int value = sqlite3_column_int(m_stmt, column);
    VcoreLogD("    Value: %i", value);
    return value;
}

int8_t SqlConnection::DataCommand::GetColumnInt8(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column int8: [%i]", column);
    CheckColumnIndex(column);
    int8_t value = static_cast<int8_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return value;
}

int16_t SqlConnection::DataCommand::GetColumnInt16(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column int16: [%i]", column);
    CheckColumnIndex(column);
    int16_t value = static_cast<int16_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return value;
}

int32_t SqlConnection::DataCommand::GetColumnInt32(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column int32: [%i]", column);
    CheckColumnIndex(column);
    int32_t value = static_cast<int32_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return value;
}

int64_t SqlConnection::DataCommand::GetColumnInt64(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column int64: [%i]", column);
    CheckColumnIndex(column);
    int64_t value = static_cast<int64_t>(sqlite3_column_int64(m_stmt, column));
    VcoreLogD("    Value: %lli", value);
    return value;
}

float SqlConnection::DataCommand::GetColumnFloat(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column float: [%i]", column);
    CheckColumnIndex(column);
    float value = static_cast<float>(sqlite3_column_double(m_stmt, column));
    VcoreLogD("    Value: %f", value);
    return value;
}

double SqlConnection::DataCommand::GetColumnDouble(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column double: [%i]", column);
    CheckColumnIndex(column);
    double value = sqlite3_column_double(m_stmt, column);
    VcoreLogD("    Value: %f", value);
    return value;
}

std::string SqlConnection::DataCommand::GetColumnString(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column string: [%i]", column);
    CheckColumnIndex(column);

    const char *value = reinterpret_cast<const char *>(
            sqlite3_column_text(m_stmt, column));

    VcoreLogD("    Value: %s", value);

    if (value == NULL) {
        return std::string();
    }

    return std::string(value);
}

boost::optional<int> SqlConnection::DataCommand::GetColumnOptionalInteger(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional integer: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int>();
    }
    int value = sqlite3_column_int(m_stmt, column);
    VcoreLogD("    Value: %i", value);
    return boost::optional<int>(value);
}

boost::optional<int8_t> SqlConnection::DataCommand::GetColumnOptionalInt8(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional int8: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int8_t>();
    }
    int8_t value = static_cast<int8_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return boost::optional<int8_t>(value);
}

boost::optional<int16_t> SqlConnection::DataCommand::GetColumnOptionalInt16(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional int16: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int16_t>();
    }
    int16_t value = static_cast<int16_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return boost::optional<int16_t>(value);
}

boost::optional<int32_t> SqlConnection::DataCommand::GetColumnOptionalInt32(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional int32: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int32_t>();
    }
    int32_t value = static_cast<int32_t>(sqlite3_column_int(m_stmt, column));
    VcoreLogD("    Value: %i", value);
    return boost::optional<int32_t>(value);
}

boost::optional<int64_t> SqlConnection::DataCommand::GetColumnOptionalInt64(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional int64: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int64_t>();
    }
    int64_t value = static_cast<int64_t>(sqlite3_column_int64(m_stmt, column));
    VcoreLogD("    Value: %lli", value);
    return boost::optional<int64_t>(value);
}

boost::optional<float> SqlConnection::DataCommand::GetColumnOptionalFloat(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional float: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<float>();
    }
    float value = static_cast<float>(sqlite3_column_double(m_stmt, column));
    VcoreLogD("    Value: %f", value);
    return boost::optional<float>(value);
}

boost::optional<double> SqlConnection::DataCommand::GetColumnOptionalDouble(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional double: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<double>();
    }
    double value = sqlite3_column_double(m_stmt, column);
    VcoreLogD("    Value: %f", value);
    return boost::optional<double>(value);
}

boost::optional<String> SqlConnection::DataCommand::GetColumnOptionalString(
    SqlConnection::ColumnIndex column)
{
    VcoreLogD("SQL data command get column optional string: [%i]", column);
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<String>();
    }
    const char *value = reinterpret_cast<const char *>(
            sqlite3_column_text(m_stmt, column));
    VcoreLogD("    Value: %s", value);
    String s = FromUTF8String(value);
    return boost::optional<String>(s);
}

void SqlConnection::Connect(const std::string &address,
                            Flag::Type type,
                            Flag::Option flag)
{
    if (m_connection != NULL) {
        VcoreLogD("Already connected.");
        return;
    }
    VcoreLogD("Connecting to DB: %s...", address.c_str());

    // Connect to database
    int result;
    if (type & Flag::UseLucene) {
        result = db_util_open_with_options(
                address.c_str(),
                &m_connection,
                flag,
                NULL);

        m_usingLucene = true;
        VcoreLogD("Lucene index enabled");
    } else {
        result = sqlite3_open_v2(
                address.c_str(),
                &m_connection,
                flag,
                NULL);

        m_usingLucene = false;
        VcoreLogD("Lucene index disabled");
    }

    if (result == SQLITE_OK) {
        VcoreLogD("Connected to DB");
    } else {
        VcoreLogD("Failed to connect to DB!");
        ThrowMsg(Exception::ConnectionBroken, address);
    }

    // Enable foreign keys
    TurnOnForeignKeys();
}

void SqlConnection::Disconnect()
{
    if (m_connection == NULL) {
        VcoreLogD("Already disconnected.");
        return;
    }

    VcoreLogD("Disconnecting from DB...");

    // All stored data commands must be deleted before disconnect
    AssertMsg(m_dataCommandsCount == 0,
           "All stored procedures must be deleted"
           " before disconnecting SqlConnection");

    int result;

    if (m_usingLucene) {
        result = db_util_close(m_connection);
    } else {
        result = sqlite3_close(m_connection);
    }

    if (result != SQLITE_OK) {
        const char *error = sqlite3_errmsg(m_connection);
        VcoreLogD("SQL close failed");
        VcoreLogD("    Error: %s", error);
        Throw(Exception::InternalError);
    }

    m_connection = NULL;

    VcoreLogD("Disconnected from DB");
}

bool SqlConnection::CheckTableExist(const char *tableName)
{
    if (m_connection == NULL) {
        VcoreLogD("Cannot execute command. Not connected to DB!");
        return false;
    }

    DataCommandAutoPtr command =
        PrepareDataCommand("select tbl_name from sqlite_master where name=?;");

    command->BindString(1, tableName);

    if (!command->Step()) {
        VcoreLogD("No matching records in table");
        return false;
    }

    return command->GetColumnString(0) == tableName;
}

SqlConnection::SqlConnection(const std::string &address,
                             Flag::Type flag,
                             Flag::Option option,
                             SynchronizationObject *synchronizationObject) :
    m_connection(NULL),
    m_usingLucene(false),
    m_dataCommandsCount(0),
    m_synchronizationObject(synchronizationObject)
{
    VcoreLogD("Opening database connection to: %s", address.c_str());

    // Connect to DB
    SqlConnection::Connect(address, flag, option);

    if (!m_synchronizationObject) {
        VcoreLogD("No synchronization object defined");
    }
}

SqlConnection::~SqlConnection()
{
    VcoreLogD("Closing database connection");

    // Disconnect from DB
    Try
    {
        SqlConnection::Disconnect();
    }
    Catch(Exception::Base)
    {
        VcoreLogD("Failed to disconnect from database");
    }
}

void SqlConnection::ExecCommand(const char *format, ...)
{
    if (m_connection == NULL) {
        VcoreLogD("Cannot execute command. Not connected to DB!");
        return;
    }

    if (format == NULL) {
        VcoreLogD("Null query!");
        ThrowMsg(Exception::SyntaxError, "Null statement");
    }

    char *rawBuffer;

    va_list args;
    va_start(args, format);

    if (vasprintf(&rawBuffer, format, args) == -1) {
        rawBuffer = NULL;
    }

    va_end(args);

    std::unique_ptr<char[],free_deleter> buffer(rawBuffer);

    if (!buffer) {
        VcoreLogD("Failed to allocate statement string");
        return;
    }

    VcoreLogD("Executing SQL command: %s", buffer.get());

    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(m_synchronizationObject.get());

    for (;;) {
        char *errorBuffer;

        int ret = sqlite3_exec(m_connection,
                               buffer.get(),
                               NULL,
                               NULL,
                               &errorBuffer);

        std::string errorMsg;

        // Take allocated error buffer
        if (errorBuffer != NULL) {
            errorMsg = errorBuffer;
            sqlite3_free(errorBuffer);
        }

        if (ret == SQLITE_OK) {
            return;
        }

        if (ret == SQLITE_BUSY) {
            VcoreLogD("Collision occurred while executing SQL command");

            // Synchronize if synchronization object is available
            if (m_synchronizationObject) {
                VcoreLogD("Performing synchronization");
                m_synchronizationObject->Synchronize();
                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        VcoreLogD("Failed to execute SQL command. Error: %s", errorMsg.c_str());
        ThrowMsg(Exception::SyntaxError, errorMsg);
    }
}

SqlConnection::DataCommandAutoPtr SqlConnection::PrepareDataCommand(
    const char *format,
    ...)
{
    if (m_connection == NULL) {
        VcoreLogD("Cannot execute data command. Not connected to DB!");
        return DataCommandAutoPtr();
    }

    char *rawBuffer;

    va_list args;
    va_start(args, format);

    if (vasprintf(&rawBuffer, format, args) == -1) {
        rawBuffer = NULL;
    }

    va_end(args);

    std::unique_ptr<char[],free_deleter> buffer(rawBuffer);

    if (!buffer) {
        VcoreLogD("Failed to allocate statement string");
        return DataCommandAutoPtr();
    }

    VcoreLogD("Executing SQL data command: %s", buffer.get());

    return DataCommandAutoPtr(new DataCommand(this, buffer.get()));
}

SqlConnection::RowID SqlConnection::GetLastInsertRowID() const
{
    return static_cast<RowID>(sqlite3_last_insert_rowid(m_connection));
}

void SqlConnection::TurnOnForeignKeys()
{
    ExecCommand("PRAGMA foreign_keys = ON;");
}

void SqlConnection::BeginTransaction()
{
    ExecCommand("BEGIN;");
}

void SqlConnection::RollbackTransaction()
{
    ExecCommand("ROLLBACK;");
}

void SqlConnection::CommitTransaction()
{
    ExecCommand("COMMIT;");
}

SqlConnection::SynchronizationObject *
SqlConnection::AllocDefaultSynchronizationObject()
{
    return new NaiveSynchronizationObject();
}

int SqlConnection::db_util_open_with_options(const char *pszFilePath, sqlite3 **ppDB,
                                int flags, const char *zVfs)
{
    int mode;

    if((pszFilePath == NULL) || (ppDB == NULL)) {
            VcoreLogW("sqlite3 handle null error");
            return SQLITE_ERROR;
    }

    mode = R_OK;

    if((geteuid() != 0) && (access(pszFilePath, mode))) {
            if(errno == EACCES) {
                    VcoreLogD("file access permission error");
                    return SQLITE_PERM;
            }
    }

    /* Open DB */
    int rc = sqlite3_open_v2(pszFilePath, ppDB, flags, zVfs);
    if (SQLITE_OK != rc) {
            VcoreLogE("sqlite3_open_v2 error(%d)",rc);
            return rc;
    }

    //rc = __db_util_open(*ppDB);

    return rc;
}


int SqlConnection::db_util_close(sqlite3 *pDB)
{
    char *pszErrorMsg = NULL;

    /* Close DB */
    int rc = sqlite3_close(pDB);
    if (SQLITE_OK != rc) {
            VcoreLogW("Fail to change journal mode: %s\n", pszErrorMsg);
            sqlite3_free(pszErrorMsg);
            return rc;
    }

    return SQLITE_OK;
}

} // namespace DB
} // namespace VcoreDPL
