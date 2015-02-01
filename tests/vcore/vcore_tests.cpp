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
 * @file        main.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of main
 */
#include <dpl/test/test_runner.h>
#include <dpl/db/orm.h>

#ifdef _WEARABLE
#include <dpl/optional.h>
#else
#include <boost/optional.hpp>
#endif

#include <vcore/VCore.h>

#include <libsoup/soup.h> // includes headers with g_type_init

int main (int argc, char *argv[])
{
	int status = -1;

	g_type_init();
//	g_thread_init(NULL);
	ValidationCore::VCoreInit(
		"/usr/share/wrt-engine/fingerprint_list.xml",
		"/usr/share/wrt-engine/fingerprint_list.xsd",
		"/opt/dbspace/.cert_svc_vcore.db");
	Try
	{
		ValidationCore::AttachToThreadRW();
		status = DPL::Test::TestRunnerSingleton::Instance().ExecTestRunner(argc, argv);
		ValidationCore::DetachFromThread();
	}
	Catch(DPL::ThreadLocalVariable<DPL::DB::SqlConnection*>::Exception::NullReference)
	{
		status = -1;
	}catch(...)
	{
		return 0;
	}
	ValidationCore::VCoreDeinit();

	return status;
}

