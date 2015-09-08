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
 * @file        wrt_crypto_hash.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of cryptographic hasing algorithms
 */
#include <vcore/CryptoHash.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <stdexcept>

#include <vcore/Base64.h>

namespace ValidationCore
{
namespace Crypto
{
namespace Hash
{
namespace // anonymous
{
const size_t HASH_DIGEST_STREAM_FEED_SIZE = 1024;
} // namespace anonymous

Base::Base()
    : m_hasFinal(false)
{
}

Base::~Base()
{
}

void Base::Append(const char *buffer)
{
    if (m_hasFinal)
        VcoreThrowMsg(Crypto::Hash::OutOfSequence,
                      "Cannot append hash after final update!");

    HashUpdate(buffer, strlen(buffer));
}

void Base::Append(const char *buffer, size_t bufferSize)
{
    if (m_hasFinal)
        VcoreThrowMsg(Crypto::Hash::OutOfSequence,
                      "Cannot append hash after final update!");

    HashUpdate(buffer, bufferSize);
}

void Base::Append(const std::string &buffer)
{
    if (m_hasFinal)
        VcoreThrowMsg(Crypto::Hash::OutOfSequence,
                 "Cannot append hash after final update!");

    HashUpdate(buffer.c_str(), buffer.size());
}

void Base::Append(std::istream &stream)
{
    if (m_hasFinal)
        VcoreThrowMsg(Crypto::Hash::OutOfSequence,
                 "Cannot append hash after final update!");

    char buffer[HASH_DIGEST_STREAM_FEED_SIZE];

    do
    {
        stream.read(buffer, HASH_DIGEST_STREAM_FEED_SIZE);

        if (stream.gcount() > 0)
            Append(static_cast<void *>(buffer), static_cast<size_t>(stream.gcount()));

    } while (stream.gcount() > 0);
}

void Base::Append(const void *data, size_t dataSize)
{
    if (m_hasFinal)
        VcoreThrowMsg(Crypto::Hash::OutOfSequence,
                 "Cannot append hash after final update!");

    HashUpdate(data, dataSize);
}

void Base::Finish()
{
    if (m_hasFinal)
        return;

    // Finalize hashing algorithm
    m_raw = HashFinal();

    // Convert to base 64 string
    Base64Encoder encoder;
    encoder.reset();
    encoder.append(std::string(m_raw.begin(), m_raw.end()));
    encoder.finalize();
    m_base64StringHash = encoder.get();

    m_hasFinal = true;
}

std::string Base::ToBase64String() const
{
    return m_base64StringHash;
}

Raw Base::GetHash() const
{
    return m_raw;
}

OpenSSL::OpenSSL(const EVP_MD *evpMd)
    : m_finalized(false)
{
    EVP_MD_CTX_init(&m_context);

    if (EVP_DigestInit(&m_context, evpMd) != 1)
        VcoreThrowMsg(Crypto::Hash::AppendFailed,
                      "EVP_DigestInit failed!");
}

OpenSSL::~OpenSSL()
{
    if (!m_finalized)
    {
        // Just clean context
        EVP_MD_CTX_cleanup(&m_context);
        m_finalized = true;
    }
}

void OpenSSL::HashUpdate(const void *data, size_t dataSize)
{
    if (m_finalized)
        VcoreThrowMsg(Crypto::Hash::AppendFailed,
                      "OpenSSLHash hash already finalized!");

    if (EVP_DigestUpdate(&m_context, data, dataSize) != 1)
        VcoreThrowMsg(Crypto::Hash::AppendFailed,
                      "EVP_DigestUpdate failed!");
}

Hash::Raw OpenSSL::HashFinal()
{
    if (m_finalized)
        VcoreThrowMsg(Crypto::Hash::AppendFailed,
                 "OpenSSLHash hash already finalized!");

    unsigned char hash[EVP_MAX_MD_SIZE] = {};
    unsigned int hashLength;

    // Also cleans context
    if (EVP_DigestFinal(&m_context, hash, &hashLength) != 1)
        VcoreThrowMsg(Crypto::Hash::AppendFailed,
                      "EVP_DigestFinal failed!");

    m_finalized = true;
    return Raw(hash, hash + hashLength);
}

} // namespace Hash
} // namespace Crypto
} // namespace ValidationCore
