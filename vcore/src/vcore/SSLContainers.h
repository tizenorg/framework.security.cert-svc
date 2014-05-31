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
#ifndef _SSLCONTAINERS_H
#define _SSLCONTAINERS_H

#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

/*
 * default deleter functor with no overloaded operator()
 */
template <typename T>
struct MySSLFree {};

/*
 * macro for defining custom deleters for openssl structs
 * usage DECLARE_DELETER(OpenSSLType)
 */
#define DECLARE_DELETER(Type) template<> \
    struct MySSLFree <Type>                  \
    {                                        \
        void operator() (Type* p)            \
        {                                    \
            Type ## _free(p);                  \
        }                                    \
                                         \
    };

/*
 * declare custom deleter for X509 structs
 */
DECLARE_DELETER(X509)
/*
 * declare custom deleter for OCSP_REQUEST structs
 */
DECLARE_DELETER(OCSP_REQUEST)
/*
 * declare custom deleter for OCSP_RESPONSE structs
 */
DECLARE_DELETER(OCSP_RESPONSE)
/*
 * declare custom deleter for OCSP_CERTID structs
 */
DECLARE_DELETER(OCSP_CERTID)
/*
 * declare custom deleter for OCSP_BASICRESP structs
 */
DECLARE_DELETER(OCSP_BASICRESP)
/*
 * declare custom deleter for X509_STORE structs
 */
DECLARE_DELETER(X509_STORE)

/*
 * undef it, so anyone could use that macro name
 */
#undef DECLARE_DELETER

/*
 * OpenSSL smart container
 * usage SSLSmartContainer <OpenSSLType> smartptr = ptrToOpenSSLType
 * remember to add OpenSSLType to macro list few lines above
 */
template <typename T, typename deleter = MySSLFree<T> >
class SSLSmartContainer
{
  public:
    SSLSmartContainer() : m_pData(NULL)
    {
    }

    /*
     * explicit constructor, we don't want any auto casting
     */
    explicit SSLSmartContainer(T* pData)
    {
        m_pData = pData;
    }

    /*
     * overloaded assignment operator
     */
    SSLSmartContainer & operator=(SSLSmartContainer& pContainer)
    {
        /*
         * check if no assignment was done before
         */
        if (this != &pContainer) {
            // if so, free internal data
            deleter ssl_free;
            ssl_free(m_pData);

            // and assign new
            m_pData = pContainer.m_pData;

            pContainer.m_pData = NULL;
        }

        return *this;
    }

    SSLSmartContainer & operator=(T* pData)
    {
        /*
         * check if no assignment was done before
         */
        if (m_pData != pData) {
            // if so, free internal data
            deleter ssl_free;
            ssl_free(m_pData);

            // and assign new
            m_pData = pData;
        }

        return *this;
    }

    ~SSLSmartContainer()
    {
        deleter ssl_free;
        ssl_free(m_pData);
    }

    /*
     * overloaded operators for standardptr - like usage
     */
    SSLSmartContainer & operator*()
    {
        return *m_pData;
    }
    SSLSmartContainer* operator->()
    {
        return m_pData;
    }

    /*
     * auto cast to T operator
     */
    operator T *() const { return m_pData;
    }

    /*
     * detachs internal pointer from smart pointer
     */
    T* DetachPtr()
    {
        T* pData = m_pData;
        m_pData = NULL;
        return pData;
    }

  private:
    /*
     * blocked assignment from another types operator
     */
    template <typename S>
    T & operator = (S& pContainer)
    {
        return *this;
    }

    /*
     * internal data
     */
    T* m_pData;
};

#endif /* _SSLCONTAINERS_H */

