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
#ifndef _TEST_CRL_H
#define _TEST_CRL_H

#include <string>
#include <vcore/CRLImpl.h>
#include <vcore/CRLCacheDAO.h>

class TestCRL : public ValidationCore::CRLImpl
{
  public:
    TestCRL();

    void addCRLToStore(const std::string &filename, const std::string &uri);

    //convinient function
    std::string getFileContent(const std::string &filename);
};

#endif
