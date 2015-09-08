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

#include <cert-svc/ccert.h>

//#include <vcore/VCore.h>
//#include <libsoup/soup.h> // includes headers with g_type_init

CertSvcInstance vinstance;

int main (int argc, char *argv[])
{
//    g_type_init();
//    g_thread_init(NULL);
    certsvc_instance_new(&vinstance);
    int status = VcoreDPL::Test::TestRunnerSingleton::Instance().ExecTestRunner(argc, argv);
    certsvc_instance_free(vinstance);
    return status;
}

