/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* To prevent inadvertently including a header twice */
#ifndef CERT_SERVICE_UTIL_H
#define CERT_SERVICE_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif	// __cplusplus
/*********************************************************************************/
/* Variable definitions                                                          */
/*********************************************************************************/

/*********************************************************************************/
/* Function definitions                                                          */
/*********************************************************************************/
int get_content_into_buf_PEM(unsigned char* content, cert_svc_mem_buff* cert);
int get_content_into_buf_DER(unsigned char* content, cert_svc_mem_buff* cert);

int cert_svc_util_get_file_size(const char* filepath, unsigned long int* length);
int cert_svc_util_load_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf);
int cert_svc_util_load_PFX_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf, cert_svc_linked_list* certLink, unsigned char** privateKey, int* priKeyLen, char* passPhrase);
int cert_svc_util_get_cert_path(const char* fileName, const char* location, char* retBuf);
int cert_svc_util_base64_encode(char* in, int inLen, char* out, int* outLen);
int cert_svc_util_base64_decode(char* in, int inLen, char* out, int* outLen);

#ifdef __cplusplus
}
#endif	// __cplusplus

#endif	// CERT_SERVICE_UTIL_H
