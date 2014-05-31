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
 * @file
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_VALIDATORFACTORY_H_
#define _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_VALIDATORFACTORY_H_

#include <CertificateIdentifier.h>

namespace ValidationCore {
// First use of CertificateIdentificator should initialized it.
// We do not want to create cyclic dependencies between
// CertificateConfigReader and CertificateIdentificator so
// we are using factory method to create CertificateIdentificator.

const CertificateIdentifier& createCertificateIdentifier();
} // namespace ValidationCore

#endif // _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_VALIDATORFACTORY_H_
