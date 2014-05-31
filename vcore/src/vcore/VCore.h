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
 * @file        VCore.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _VCORE_SRC_VCORE_VCORE_H_
#define _VCORE_SRC_VCORE_VCORE_H_

#include <string>

namespace ValidationCore {
/*
 * configFilePath - path to XML config file with certificates configuration
 *
 * configSchemaPath - XMLschema of config file
 *
 * databasePath - path to database with OCSP/CRL cache.
 *
 * This function could be run only once. If you call it twice it will
 * return false and non data will be set.
 *
 * This function must be call before AttachToThread function.
 */
bool VCoreInit(const std::string& configFilePath,
               const std::string& configSchemaPath,
               const std::string& databasePath);

/*
 * This function will free internal structures responsible for db connection.
 */
void VCoreDeinit(void);

/*
 * All thread with are using OCSP/CRL must call AttachToThread function before
 * it can call OCSP/CRL. More than one thread could be Attach with OCPS/CRL.
 *
 * You mast attach thread to OCSP/CRL because OCSP/CRL is using database
 * CertificateCachedDAO. For each thread that will be using this database
 * vcore  must create internal structure (with connection info).
 *
 */
void AttachToThreadRO(void);
void AttachToThreadRW(void);
void DetachFromThread(void);

} // namespace ValidationCore

#endif // _VCORE_SRC_VCORE_VCORE_H_

