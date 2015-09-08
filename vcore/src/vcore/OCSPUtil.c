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
 * @author      Tomasz Morawski(t.morawski@samsung.com)
 * @version     0.1
 * @brief
 */

#include <openssl/ocsp.h>

/*
 * This function is needed to fix "Invalid conversion from void* to unsigned char*"
 * C++ compiler error during calling i2d_OCSP_REQUEST_bio macro
 */
int convertToBuffer(OCSP_REQUEST *req, char **buf, int *size);

int convertToBuffer(OCSP_REQUEST *req, char **buf, int *size) {
    BIO *req_mem_bio;
    BUF_MEM req_bmem;

    /*
     * size and membuffer for request
     */
    *size = i2d_OCSP_REQUEST(req, NULL);
    *buf = (char*) malloc(*size);

    if (!*buf)
        return 0;

    /* copy request into buffer */
    req_bmem.length = 0;
    req_bmem.data = *buf;
    req_bmem.max = *size;

    /*
     * create a new buffer using openssl
     */
    req_mem_bio = BIO_new(BIO_s_mem());

    if (!req_mem_bio) {
        /*
         * creation failed, return
         */
        free(*buf);
        *buf = NULL;
        return 0;
    }

    BIO_set_mem_buf(req_mem_bio, &req_bmem, BIO_NOCLOSE);

    /*
     * prepare request
     */
    if (i2d_OCSP_REQUEST_bio(req_mem_bio, req) <= 0) {
        free(*buf);
        *buf = NULL;
        BIO_free_all(req_mem_bio);
        return 0;
    }

    /*
     *  check consistency
     */
    if (*size != ((int)req_bmem.length) || req_bmem.length != req_bmem.max)
    {
        free(*buf);
        *buf = NULL;
        BIO_free_all(req_mem_bio);
        return 0;
    }

    /*
     * free all reserved memory
     */
    BIO_free_all(req_mem_bio);

    /*
     * and return success
     */
    return 1;
}
