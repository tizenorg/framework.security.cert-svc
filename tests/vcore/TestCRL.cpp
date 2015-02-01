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
#include <algorithm>
#include <cstring>
#include <openssl/x509v3.h>
#include <file_input_mapping.h>
#include <dpl/log/log.h>
#include "TestCRL.h"

using namespace ValidationCore;
using namespace std;


namespace {
const char *CRL_LOOKUP_DIR = "/opt/etc/ssl/certs/";
const char *beginCertificate = "-----BEGIN CERTIFICATE-----";
const char *endCertificate = "-----END CERTIFICATE-----";
const char *beginTrustedCertificate = "-----BEGIN TRUSTED CERTIFICATE-----";
const char *endTrustedCertificate = "-----END TRUSTED CERTIFICATE-----";


bool whiteCharacter(char a){
    return a == '\n';
}

}

TestCRL::TestCRL()
  : CRLImpl (new CRLCacheDAO)
{
    //Add additional lookup dir
    int rv = X509_LOOKUP_add_dir(m_lookup, CRL_LOOKUP_DIR, X509_FILETYPE_PEM);
    if (!rv) {
        LogError("Failed to add lookup dir for PEM files.");
        ThrowMsg(CRLException::StorageError,
                "Failed to add lookup dir for PEM files.");
    }
    LogInfo("CRL storage initialization complete.");
}

std::string TestCRL::getFileContent(const std::string &filename)
{
    //Only PEM formatted files allowed
    LogInfo("Read file: " << filename);
    FileInputMapping file(filename);
    string content(reinterpret_cast<const char*>(file.GetAddress()),
            file.GetSize());

    size_t posBegin = content.find(beginCertificate);
    size_t posEnd = content.find(endCertificate);
    if (posBegin != string::npos &&
        posEnd != string::npos) {
        posBegin += strlen(beginCertificate);
    } else {
        posBegin = content.find(beginTrustedCertificate);
        posEnd = content.find(endTrustedCertificate);
        if (posBegin != string::npos &&
            posEnd != string::npos) {
            posBegin += strlen(beginTrustedCertificate);
        } else {
            LogError("Failed to parse PEM file");
            return string();
        }
    }
    //Remove whitespaces
    string cert(content, posBegin, posEnd - posBegin);
    cert.erase(std::remove_if(cert.begin(), cert.end(), whiteCharacter),
            cert.end());

    return cert;
}

void TestCRL::addCRLToStore(const string &filename, const string &uri)
{
    LogInfo("Read file: " << filename);
    //Only PEM formatted files allowed
    FileInputMapping file(filename);
    char *buffer = new char[file.GetSize()];
    memcpy(buffer, file.GetAddress(), file.GetSize());
    CRLDataPtr crl(new  CRLData(buffer, file.GetSize(), uri));
    updateCRL(crl);
}
