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
#include <dpl/log/wrt_log.h>

#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <istream>
#include <sstream>
#include <memory>
#include <functional>

#include <pcrecpp.h>

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
    std::unique_ptr<DIR, std::function<int(DIR*)>>
        dp(::opendir(m_dir.c_str()), ::closedir);

    if (dp.get() == NULL) {
        WrtLogE("Error opening directory: %s", m_dir.c_str());
        return ERROR_OPENING_DIR;
    }

    size_t len = offsetof(struct dirent, d_name)
        + pathconf(m_dir.c_str(), _PC_NAME_MAX) + 1;

    std::unique_ptr<struct dirent, std::function<void(void*)>>
        pEntry(static_cast<struct dirent *>(::malloc(len)), ::free);

    struct dirent *dirp = NULL;

    int ret = 0;
    while ((ret = readdir_r(dp.get(), pEntry.get(), &dirp)) == 0 && dirp) {
        if (strcmp(dirp->d_name, SIGNATURE_AUTHOR) == 0) {
            set.insert(SignatureFileInfo(std::string(dirp->d_name), -1));
            continue;
        }

        std::string sig, num, xml;
        if (m_signatureRegexp.FullMatch(dirp->d_name, &sig, &num, &xml)) {
            std::istringstream stream(num);
            int number;
            stream >> number;

            if (stream.fail())
                return ERROR_ISTREAM;

            set.insert(SignatureFileInfo(std::string(dirp->d_name), number));
        }
    }

    if (ret != 0) {
        WrtLogE("Error in readdir_r");
        return ERROR_READING_DIR;
    }

    return NO_ERROR;
}

SignatureFinder::SignatureFinder(const std::string& dir)
  : m_impl(new Impl(dir))
{}

SignatureFinder::~SignatureFinder()
{
    delete m_impl;
}

SignatureFinder::Result SignatureFinder::find(SignatureFileInfoSet &set) {
    return m_impl->find(set);
}

} // namespace ValidationCore
