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
 * @file        crypto_hash.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of cryptographic hasing algorithms
 */
#ifndef _CRYPTO_HASH_H_
#define _CRYPTO_HASH_H_

#include <dpl/exception.h>
#include <openssl/evp.h>
#include <istream>
#include <string>
#include <vector>

namespace ValidationCore
{
namespace Crypto
{
namespace Hash
{
/**
 * Raw hash buffer
 */
typedef std::vector<unsigned char> Raw;

/**
 * Append called out of sequence
 */
DECLARE_EXCEPTION_TYPE(DPL::Exception, OutOfSequence)

/**
 * Append failed internally
 */
DECLARE_EXCEPTION_TYPE(DPL::Exception, AppendFailed)

class Base
{
private:
    Raw m_raw;
    std::string m_base64StringHash;
    bool m_hasFinal;

protected:
    virtual void HashUpdate(const void *data, size_t dataSize) = 0;
    virtual Raw HashFinal() = 0;

public:
    Base();
    virtual ~Base();

    virtual void Append(const char *buffer);
    virtual void Append(const char *buffer, size_t bufferSize);
    virtual void Append(const std::string &buffer);
    virtual void Append(std::istream &stream);
    virtual void Append(const void *data, size_t dataSize);

    virtual void Finish();

    virtual std::string ToBase64String() const;
    virtual Raw GetHash() const;
};

/**
 * OpenSSL hashing algorithm base
 */
class OpenSSL
    : public Base
{
private:
    EVP_MD_CTX m_context;
    bool m_finalized;

protected:
    virtual void HashUpdate(const void *data, size_t dataSize);
    virtual Raw HashFinal();

public:
    OpenSSL(const EVP_MD *evpMd);
    virtual ~OpenSSL();
};

#define DECLARE_OPENSSL_HASH_ALGORITHM(ClassName, EvpMd) \
    class ClassName                                      \
        : public OpenSSL                                 \
    {                                                    \
    public:                                              \
        ClassName() : OpenSSL(EvpMd()) {}                \
        virtual ~ClassName() {}                          \
    };

DECLARE_OPENSSL_HASH_ALGORITHM(MD2, EVP_md2)
DECLARE_OPENSSL_HASH_ALGORITHM(MD4, EVP_md4)
DECLARE_OPENSSL_HASH_ALGORITHM(MD5, EVP_md5)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA, EVP_sha)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA1, EVP_sha1)
DECLARE_OPENSSL_HASH_ALGORITHM(DSS, EVP_dss)
DECLARE_OPENSSL_HASH_ALGORITHM(DSS1, EVP_dss1)
DECLARE_OPENSSL_HASH_ALGORITHM(ECDSA, EVP_ecdsa)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA224, EVP_sha224)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA256, EVP_sha256)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA384, EVP_sha384)
DECLARE_OPENSSL_HASH_ALGORITHM(SHA512, EVP_sha512)

#undef DECLARE_OPENSSL_HASH_ALGORITHM

} // namespace Hash
} // namespace Crypto
} // namespace ValidationCore

#endif // DPL_CRYPTO_HASH_H
