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
 * @file    thread_database_support.h
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk)
 * @version 1.0
 * @brief   This file contains the declaration of thread database support
 */

#ifndef DPL_THREAD_DATABASE_SUPPORT_H
#define DPL_THREAD_DATABASE_SUPPORT_H

#include <string>
#include <dpl/db/sql_connection.h>
#include <dpl/db/orm_interface.h>
#include <dpl/thread.h>
#include <dpl/assert.h>
#include <stdint.h>

namespace VcoreDPL {
namespace DB {
/**
 * Thread database support
 *
 * Associate database connection with thread lifecycle
 *
 */

class ThreadDatabaseSupport :
    public VcoreDPL::DB::ORM::IOrmInterface
{
  private:
    typedef VcoreDPL::DB::SqlConnection *SqlConnectionPtr;
    typedef VcoreDPL::ThreadLocalVariable<SqlConnectionPtr> TLVSqlConnectionPtr;
    typedef VcoreDPL::ThreadLocalVariable<size_t> TLVSizeT;
    typedef VcoreDPL::ThreadLocalVariable<bool> TLVBool;

    TLVSqlConnectionPtr m_connection;
    TLVBool m_linger;
    TLVSizeT m_refCounter;
    TLVSizeT m_transactionDepth;
    TLVSizeT m_attachCount;
    TLVBool m_transactionCancel;
    std::string m_address;
    VcoreDPL::DB::SqlConnection::Flag::Type m_flags;

    TLVSqlConnectionPtr &Connection()
    {
        return m_connection;
    }

    TLVBool &Linger()
    {
        return m_linger;
    }

    TLVSizeT &RefCounter()
    {
        return m_refCounter;
    }

    TLVSizeT &TransactionDepth()
    {
        return m_transactionDepth;
    }

    TLVSizeT &AttachCount()
    {
        return m_attachCount;
    }

    TLVBool &TransactionCancel()
    {
        return m_transactionCancel;
    }

    void CheckedConnectionDelete()
    {
        Assert(!Connection().IsNull());
        Assert(*Linger() == true);

        if (*RefCounter() > 0 || *AttachCount() > 0) {
            return;
        }

        // Destroy connection
        VcoreLogD("Destroying thread database connection: %s", m_address.c_str());

        delete *Connection();

        // Blocking destroy
        Connection().GuardValue(false);
        Linger().GuardValue(false);
        RefCounter().GuardValue(false);
        TransactionCancel().GuardValue(false);
        TransactionDepth().GuardValue(false);
        AttachCount().GuardValue(false);

        Connection().Reset();
        Linger().Reset();
        RefCounter().Reset();
        TransactionCancel().Reset();
        TransactionDepth().Reset();
        AttachCount().Reset();
    }

    void TransactionUnref()
    {
        VcoreLogD("Unref transaction");

        if (--(*TransactionDepth()) == 0) {
            VcoreLogD("Transaction is finalized");

            if (*TransactionCancel()) {
                VcoreLogD("Transaction will be rolled back");
                (*Connection())->RollbackTransaction();
            } else {
                VcoreLogD("Transaction will be commited");
                (*Connection())->CommitTransaction();
            }
        }
    }

  public:
    ThreadDatabaseSupport(const std::string &address,
                          VcoreDPL::DB::SqlConnection::Flag::Type flags) :
        m_address(address),
        m_flags(flags)
    {}

    virtual ~ThreadDatabaseSupport()
    {}

    void AttachToThread(
        VcoreDPL::DB::SqlConnection::Flag::Option options =
            VcoreDPL::DB::SqlConnection::Flag::RO)
    {
        Linger() = false;

        if (!Connection().IsNull()) {
            // Add reference
            ++*AttachCount();
            return;
        }

        // Initialize SQL connection described in traits
        VcoreLogD("Attaching thread database connection: %s", m_address.c_str());

        Connection() = new VcoreDPL::DB::SqlConnection(
                m_address.c_str(), m_flags, options);

        RefCounter() = 0;

        AttachCount() = 1;

        //Init Transaction related variables
        TransactionDepth() = 0;
        TransactionCancel() = false;

        // Blocking destroy
        Connection().GuardValue(true);
        Linger().GuardValue(true);
        RefCounter().GuardValue(true);
        TransactionDepth().GuardValue(true);
        AttachCount().GuardValue(true);
        TransactionCancel().GuardValue(true);
    }

    void DetachFromThread()
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        // Remove reference
        --*AttachCount();

        if (*AttachCount() > 0) {
            return;
        }

        // It must not be in linger state yet
        Assert(*Linger() == false);

        VcoreLogD("Detaching thread database connection: %s", m_address.c_str());

        // Enter linger state
        *Linger() = true;

        // Checked delete
        CheckedConnectionDelete();
    }

    bool IsAttached()
    {
        return !AttachCount().IsNull() && *AttachCount() > 0;
    }

    VcoreDPL::DB::SqlConnection::DataCommand *AllocDataCommand(
        const std::string &statement)
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        // Calling thread must not be in linger state
        Assert(*Linger() == false);

        // Add reference
        ++*RefCounter();

        // Create new unmanaged data command
        return (*Connection())->PrepareDataCommand(statement.c_str()).release();
    }

    void FreeDataCommand(VcoreDPL::DB::SqlConnection::DataCommand *command)
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        // Delete data command
        delete command;

        // Unreference SQL connection
        --*RefCounter();

        // If it is linger state, connection may be destroyed
        if (*Linger() == true) {
            CheckedConnectionDelete();
        }
    }

    void TransactionBegin()
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        VcoreLogD("Begin transaction");

        // Addref transaction
        if (++(*TransactionDepth()) == 1) {
            VcoreLogD("Transaction is initialized");

            TransactionCancel() = false;
            (*Connection())->BeginTransaction();
        }
    }

    void TransactionCommit()
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        VcoreLogD("Commit transaction");

        // Unref transation
        TransactionUnref();
    }

    void TransactionRollback()
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        // Cancel and unref transaction
        TransactionCancel() = true;
        TransactionUnref();
    }

    VcoreDPL::DB::SqlConnection::RowID GetLastInsertRowID()
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        return (*Connection())->GetLastInsertRowID();
    }

    bool CheckTableExist(const char *name)
    {
        // Calling thread must support thread database connections
        Assert(!Connection().IsNull());

        return (*Connection())->CheckTableExist(name);
    }
};
}
}

#endif // DPL_THREAD_DATABASE_SUPPORT_H
