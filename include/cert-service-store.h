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
#ifndef CERT_SERVICE_STORE_H
#define CERT_SERVICE_STORE_H

#ifdef __cplusplus
extern "C" {
#endif	// __cplusplus

int get_file_full_path(char* originalName, const char* location, char* outBuf);
int _add_certificate_to_store(const char* filePath, const char* location);
int _delete_certificate_from_store(const char* filePath, const char* location);

#ifdef __cplusplus
}
#endif	// __cplusplus

#endif	// CERT_SERVICE_STORE_H
