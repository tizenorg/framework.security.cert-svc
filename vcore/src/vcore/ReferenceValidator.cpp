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
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @file        ReferenceValidator.cpp
 * @version     1.0
 * @brief       Compare signature reference list and list of widget file.
 */
#include <vcore/ReferenceValidator.h>

#include <stddef.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fstream>
#include <memory>
#include <functional>

#include <pcrecpp.h>

#include <dpl/errno_string.h>
#include <dpl/log/wrt_log.h>

namespace {

const char *SPECIAL_SYMBOL_CURRENT_DIR = ".";
const char *SPECIAL_SYMBOL_UPPER_DIR = "..";
const char *SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE = "author-signature.xml";
const char *REGEXP_DISTRIBUTOR_SIGNATURE = "^signature[1-9][0-9]*\\.xml";

const char MARK_ENCODED_CHAR = '%';

} // namespace anonymous

namespace ValidationCore {

class ReferenceValidator::Impl
{
  public:
    Impl(const std::string &dirpath)
      : m_dirpath(dirpath)
      , m_signatureRegexp(REGEXP_DISTRIBUTOR_SIGNATURE)
    {}

    virtual ~Impl(){}

    Result checkReferences(const SignatureData &signatureData){
        const ReferenceSet &refSet = signatureData.getReferenceSet();
        ReferenceSet refDecoded;

        try {
            for (auto it = refSet.begin(); it != refSet.end(); ++it) {
                if (std::string::npos != it->find(MARK_ENCODED_CHAR))
                    refDecoded.insert(decodeProcent(*it));
                else
                    refDecoded.insert(*it);
            }
        } catch (Result &) {
            return ERROR_DECODING_URL;
        }
        return dfsCheckDirectories(
            refDecoded,
            std::string(),
            signatureData.isAuthorSignature());
    }

  private:
    int hexToInt(char hex);
    std::string decodeProcent(const std::string &path);

    Result dfsCheckDirectories(
        const ReferenceSet &referenceSet,
        const std::string &directory,
        bool isAuthorSignature);

    inline bool isDistributorSignature(const char *cstring) const
    {
        return m_signatureRegexp.FullMatch(cstring);
    }

    std::string m_dirpath;
    std::string m_errorDescription;
    pcrecpp::RE m_signatureRegexp;
};

int ReferenceValidator::Impl::hexToInt(char a) {
    if (a >= '0' && a <= '9') return a-'0';
    if (a >= 'A' && a <= 'F') return a-'A' + 10;
    if (a >= 'a' && a <= 'f') return a-'a' + 10;
    WrtLogE("Symbol '%c' is out of scope.", a);
    throw ERROR_DECODING_URL;
}

std::string ReferenceValidator::Impl::decodeProcent(const std::string &path) {
    std::vector<int> input(path.begin(), path.end());
    std::vector<char> output;
    try {
        size_t i = 0;
        while(i<input.size()) {
            if (MARK_ENCODED_CHAR == input[i]) {
                if (i+2 >= input.size())
                    throw ERROR_DECODING_URL;

                int result = hexToInt(input[i+1])*16 + hexToInt(input[i+2]);

                // RFC 1738 - octets 80 to FF are not allowed
                if (result >= 128)
                    throw ERROR_DECODING_URL;

                output.push_back(static_cast<char>(result));
                i+=3;
            } else {
                output.push_back(static_cast<char>(input[i]));
                ++i;
            }
        }
    } catch (Result &) {
        WrtLogE("Error while decoding url path: %s", path.c_str());
        throw ERROR_DECODING_URL;
    }
    return std::string(output.begin(), output.end());
}

ReferenceValidator::Result ReferenceValidator::Impl::dfsCheckDirectories(
    const ReferenceSet &referenceSet,
    const std::string &directory,
    bool isAuthorSignature)
{
    std::string currentDir = m_dirpath + directory;

    std::unique_ptr<DIR, std::function<int(DIR*)>>
        dp(::opendir(currentDir.c_str()), ::closedir);
    if (dp.get() == NULL) {
        WrtLogE("Error opening directory: %s", currentDir.c_str());
        m_errorDescription = currentDir;
        return ERROR_OPENING_DIR;
    }

    size_t len = offsetof(struct dirent, d_name)
        + pathconf(currentDir.c_str(), _PC_NAME_MAX) + 1;

    std::unique_ptr<struct dirent, std::function<void(void*)>>
        pEntry(static_cast<struct dirent *>(::malloc(len)), ::free);

    struct dirent *dirp = NULL;

    int ret = 0;
    while ((ret = readdir_r(dp.get(), pEntry.get(), &dirp)) == 0 && dirp) {

        if (!strcmp(dirp->d_name, SPECIAL_SYMBOL_CURRENT_DIR))
            continue;

        if (!strcmp(dirp->d_name, SPECIAL_SYMBOL_UPPER_DIR))
            continue;

        if (currentDir == m_dirpath
            && dirp->d_type == DT_REG
            && !strcmp(dirp->d_name, SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE)
            && isAuthorSignature)
            continue;

        if (currentDir == m_dirpath
            && dirp->d_type == DT_REG
            && isDistributorSignature(dirp->d_name))
            continue;

        if (dirp->d_type == DT_DIR) {
            WrtLogD("Open directory: %s", (directory + dirp->d_name).c_str());
            std::string tmp_directory = directory + dirp->d_name + "/";
            Result result = dfsCheckDirectories(referenceSet,
                                                tmp_directory,
                                                isAuthorSignature);
            if (result != NO_ERROR)
                return result;

        } else if (dirp->d_type == DT_REG) {
            WrtLogD("Found file: %s", (directory + dirp->d_name).c_str());

            if (referenceSet.end() == referenceSet.find(directory + dirp->d_name)) {
                WrtLogE("Unknown ERROR_REFERENCE_NOT_FOUND.");
                m_errorDescription = directory + dirp->d_name;
                return ERROR_REFERENCE_NOT_FOUND;
            }
        } else {
            WrtLogE("Unknown file type.");
            m_errorDescription = directory + dirp->d_name;
            return ERROR_UNSUPPORTED_FILE_TYPE;
        }
    }

    if (ret != 0) {
        m_errorDescription = VcoreDPL::GetErrnoString();
        WrtLogE("readdir failed. ret: %d, errno: %d, Description: %s",
            ret, errno, m_errorDescription.c_str());
        return ERROR_READING_DIR;
    }

    return NO_ERROR;
}

ReferenceValidator::ReferenceValidator(const std::string &dirpath)
  : m_impl(new Impl(dirpath))
{}

ReferenceValidator::~ReferenceValidator(){
    delete m_impl;
}

ReferenceValidator::Result ReferenceValidator::checkReferences(
    const SignatureData &signatureData)
{
    return m_impl->checkReferences(signatureData);
}

} // ValidationCore
