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
 * @file        DeveloperModeValidator.h
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @version     1.0
 * @brief       DeveloperModeValidatorValidator - implementing WAC 2.0 spec, including TargetRestriction
 */
#ifndef _VALIDATION_CORE_DEVELOPER_MODE_VALIDATOR_H_
#define _VALIDATION_CORE_DEVELOPER_MODE_VALIDATOR_H_

#include <string>
#include <dpl/exception.h>
#include <vcore/SignatureData.h>

namespace ValidationCore {

class DeveloperModeValidator
{
  public:
    explicit DeveloperModeValidator(
        bool complianceMode = false,
        const std::string &fakeIMEI = "",
        const std::string &fakeMEID = "")  __attribute__((deprecated));

    explicit DeveloperModeValidator(bool complianceMode = false,
                                    bool developerMode = false,
                                    const std::string &fakeIMEI = "",
                                    const std::string &fakeMEID = "",
                                    const std::string &realMEID = "");

    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, UnableToLoadTestCertificate)
        DECLARE_EXCEPTION_TYPE(Base, NoTargetRestrictionSatisfied)
    };

    void check(const SignatureData &data);
  private:
    bool m_complianceModeEnabled;
    bool m_developerModeEnabled;
    std::string m_fakeIMEI;
    std::string m_fakeMEID;
    std::string m_realMEID;
};

}
#endif /* _VALIDATION_CORE_DEVELOPER_MODE_VALIDATOR_H_ */

