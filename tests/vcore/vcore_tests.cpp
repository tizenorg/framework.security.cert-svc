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

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <dpl/db/orm.h>
#endif

#include <vcore/VCore.h>

#include <glib-object.h>

int main (int argc, char *argv[])
{
	int status = -1;

	ValidationCore::VCoreInit(
		"/usr/share/wrt-engine/fingerprint_list.xml",
		"/usr/share/wrt-engine/fingerprint_list.xsd",
		"/opt/dbspace/.cert_svc_vcore.db");
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
	Try
	{
#endif
		ValidationCore::AttachToThreadRW();
		status = VcoreDPL::Test::TestRunnerSingleton::Instance().ExecTestRunner(argc, argv);
		ValidationCore::DetachFromThread();
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
	}
	Catch(VcoreDPL::ThreadLocalVariable<VcoreDPL::DB::SqlConnection*>::Exception::NullReference)
	{
		status = -1;
	}catch(...)
	{
		return 0;
	}
#endif
	ValidationCore::VCoreDeinit();

	return status;
}

