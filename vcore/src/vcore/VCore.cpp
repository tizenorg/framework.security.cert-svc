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
 * @file        VCore.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @brief
 */

#include <vcore/VCorePrivate.h>
#include <vcore/Config.h>
#include <vcore/Database.h>
#include <openssl/ssl.h>
#include <database_checksum_vcore.h>
#include <glib.h>
#include <glib-object.h>

#include <dpl/assert.h>
#include <dpl/log/log.h>

namespace {
DPL::DB::ThreadDatabaseSupport *threadInterface = NULL;
} // namespace anonymous

namespace ValidationCore {

void AttachToThreadRO(void)
{
    Assert(threadInterface);
    static bool check = true;
    threadInterface->AttachToThread(
        DPL::DB::SqlConnection::Flag::RO);
    // We can have race condition here but CheckTableExist
    // is thread safe and nothing bad will happend.
    if (check) {
        check = false;
        Assert(ThreadInterface().CheckTableExist(DB_CHECKSUM_STR) &&
               "Not a valid vcore database version");
    }
}

void AttachToThreadRW(void)
{
    Assert(threadInterface);
    static bool check = true;
    threadInterface->AttachToThread(
        DPL::DB::SqlConnection::Flag::RW);
    // We can have race condition here but CheckTableExist
    // is thread safe and nothing bad will happend.
    if (check) {
        check = false;
        Assert(ThreadInterface().CheckTableExist(DB_CHECKSUM_STR) &&
               "Not a valid vcore database version");
    }
}

void DetachFromThread(void){
    Assert(threadInterface);
    threadInterface->DetachFromThread();
}

DPL::DB::ThreadDatabaseSupport& ThreadInterface(void) {
    Assert(threadInterface);
    return *threadInterface;
}

bool VCoreInit(const std::string& configFilePath,
               const std::string& configSchemaPath,
               const std::string& databasePath)
{
    if(threadInterface) {
        LogDebug("Already Initialized");
        return true;
    }

    threadInterface = new DPL::DB::ThreadDatabaseSupport(
        databasePath.c_str(),
        DPL::DB::SqlConnection::Flag::UseLucene);

    SSL_library_init();
//    g_thread_init(NULL);
    g_type_init();

    LogDebug("Initializing VCore");
    Config &globalConfig = ConfigSingleton::Instance();
    globalConfig.setXMLConfigPath(configFilePath) &&
        globalConfig.setXMLSchemaPath(configSchemaPath);

    return true;
}

void VCoreDeinit()
{
    Assert(threadInterface && "Not initialized or already deinitialized");
    delete threadInterface;
    threadInterface = NULL;
}

} // namespace ValidationCore

