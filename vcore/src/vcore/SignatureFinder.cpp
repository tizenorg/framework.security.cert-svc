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
 * @file        SignatureFinder.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Search for author-signature.xml and signatureN.xml files.
 */
#include <vcore/SignatureFinder.h>

#include <dirent.h>
#include <errno.h>
#include <istream>

#include <pcrecpp.h>

#include <dpl/log/log.h>

namespace ValidationCore {
static const char *SIGNATURE_AUTHOR = "author-signature.xml";
static const char *REGEXP_DISTRIBUTOR_SIGNATURE =
    "^(signature)([1-9][0-9]*)(\\.xml)";

class SignatureFinder::Impl {
  public:
    Impl(const std::string& dir)
      : m_dir(dir)
      , m_signatureRegexp(REGEXP_DISTRIBUTOR_SIGNATURE)
    {}

    virtual ~Impl(){}

    Result find(SignatureFileInfoSet &set);

  private:
    std::string m_dir;
    pcrecpp::RE m_signatureRegexp;
};

SignatureFinder::Result SignatureFinder::Impl::find(SignatureFileInfoSet &set)
{
    DIR *dp;
    struct dirent *dirp;

    /*
     * find a dir
     */
    if ((dp = opendir(m_dir.c_str())) == NULL) {
        LogError("Error opening directory:" << m_dir);
        return ERROR_OPENING_DIR;
    }

    for (errno = 0; (dirp = readdir(dp)) != NULL; errno = 0) {
        /**
         * check if it's author signature
         */
        if (!strcmp(dirp->d_name, SIGNATURE_AUTHOR)) {
            set.insert(SignatureFileInfo(std::string(dirp->d_name), -1));
            continue;
        }

        std::string sig, num, xml;
        if (m_signatureRegexp.FullMatch(dirp->d_name, &sig, &num, &xml)) {
            std::istringstream stream(num);
            int number;
            stream >> number;

            if (stream.fail()) {
                closedir(dp);
                return ERROR_ISTREAM;
            }

            set.insert(SignatureFileInfo(std::string(dirp->d_name), number));
        }
    }

    if (errno != 0) {
        LogError("Error in readdir");
        closedir(dp);
        return ERROR_READING_DIR;
    }

    closedir(dp);
    return NO_ERROR;
}

SignatureFinder::SignatureFinder(const std::string& dir)
  : m_impl(new Impl(dir))
{}

SignatureFinder::~SignatureFinder(){
    delete m_impl;
}

SignatureFinder::Result SignatureFinder::find(SignatureFileInfoSet &set) {
    return m_impl->find(set);
}

} // namespace ValidationCore
