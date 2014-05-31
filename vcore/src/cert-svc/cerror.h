/**
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        cerror.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */

#ifndef _CERTSVC_CERROR_H_
#define _CERTSVC_CERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CERTSVC_TRUE              (1)
#define CERTSVC_FALSE             (0)

#define CERTSVC_SUCCESS           (1)
#define CERTSVC_FAIL              (0)    /* Openssl internal error. */
#define CERTSVC_BAD_ALLOC         (-2)   /* Memmory allcation error. */
//#define CERTSVC_FILE_NOT_FOUND    (-3)   /* Certificate file does not exists. */
#define CERTSVC_WRONG_ARGUMENT    (-4)   /* Function argumnet is wrong. */
#define CERTSVC_INVALID_ALGORITHM (-5)   /* Algorithm is not supported. */
#define CERTSVC_INVALID_SIGNATURE (-6)   /* Signature and message does not match. */
#define CERTSVC_IO_ERROR          (-7)   /* Certificate file IO error. */
#define CERTSVC_INVALID_PASSWORD  (-8)   /* Certificate container password mismatch. */
#define CERTSVC_DUPLICATED_ALIAS  (-9)   /* User-provided alias is aleady taken. */

#ifdef __cplusplus
}
#endif

#endif // _CERTSVC_CERROR_H_
