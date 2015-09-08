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
 * @file        test_results_collector.h
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       Header file with declaration of TestResultsCollectorBase
 */

#ifndef DPL_TEST_RESULTS_COLLECTOR_H
#define DPL_TEST_RESULTS_COLLECTOR_H

#include <dpl/noncopyable.h>
#include <dpl/availability.h>
#include <vector>
#include <list>
#include <map>
#include <string>
#include <memory>

namespace VcoreDPL {
namespace Test {
class TestResultsCollectorBase;
typedef std::shared_ptr<TestResultsCollectorBase>
TestResultsCollectorBasePtr;

class TestResultsCollectorBase :
    private VcoreDPL::Noncopyable
{
  public:
    typedef TestResultsCollectorBase* (*CollectorConstructorFunc)();
    typedef std::list<std::string> TestCaseIdList;
    struct FailStatus
    {
        enum Type
        {
            NONE,
            FAILED,
            IGNORED,
            INTERNAL
        };
    };

    virtual ~TestResultsCollectorBase() {}

    virtual bool Configure()
    {
        return true;
    }
    virtual void Start(int count) { DPL_UNUSED_PARAM(count); }
    virtual void Finish() { }
    virtual void CollectCurrentTestGroupName(const std::string& /*groupName*/)
    {}

    virtual void CollectTestsCasesList(const TestCaseIdList& /*list*/) {}
    virtual void CollectResult(const std::string& id,
                               const std::string& description,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "") = 0;
    virtual std::string CollectorSpecificHelp() const
    {
        return "";
    }
    virtual bool ParseCollectorSpecificArg (const std::string& /*arg*/)
    {
        return false;
    }

    static TestResultsCollectorBase* Create(const std::string& name);
    static void RegisterCollectorConstructor(
        const std::string& name,
        CollectorConstructorFunc
        constructor);
    static std::vector<std::string> GetCollectorsNames();

  private:
    typedef std::map<std::string, CollectorConstructorFunc> ConstructorsMap;
    static ConstructorsMap m_constructorsMap;
};
}
}

#endif /* DPL_TEST_RESULTS_COLLECTOR_H */
