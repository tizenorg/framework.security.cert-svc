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
 * @file        pkcs12_test.cpp
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 test runner.
 */
#include <dpl/test/test_runner.h>
#include <cert-svc/ccert.h>

CertSvcInstance vinstance;

int main (int argc, char *argv[]) {
    certsvc_instance_new(&vinstance);
    int status = VcoreDPL::Test::TestRunnerSingleton::Instance().ExecTestRunner(argc, argv);
    certsvc_instance_free(vinstance);
    return status;
}
