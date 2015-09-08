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
 * @file        test_runner.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of test runner
 */
#include <stddef.h>
#include <dpl/test/test_runner.h>
#include <dpl/test/test_results_collector.h>
#include <dpl/exception.h>
#include <dpl/free_deleter.h>
#include <memory>
#include <dpl/foreach.h>
#include <dpl/log/vcore_log.h>
#include <dpl/colors.h>
#include <pcrecpp.h>
#include <algorithm>
#include <cstdio>
#include <memory.h>
#include <libgen.h>
#include <cstring>
#include <cstdlib>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <dpl/singleton_impl.h>
IMPLEMENT_SINGLETON(VcoreDPL::Test::TestRunner)

namespace {

std::string getXMLNode(xmlNodePtr node)
{
    std::string ret;
    xmlChar * value = xmlNodeGetContent(node);
    if (value != NULL) {
        ret = std::string(reinterpret_cast<char*>(value));
        xmlFree(value);
    }
    return ret;
}

}


namespace VcoreDPL {
namespace Test {
namespace // anonymous
{
std::string BaseName(std::string aPath)
{
    std::unique_ptr<char[],free_deleter> path(strdup(aPath.c_str()));
    if (NULL == path.get()) {
        throw std::bad_alloc();
    }
    char* baseName = basename(path.get());
    std::string retValue = baseName;
    return retValue;
}
} // namespace anonymous

//! \brief Failed test message creator
//!
//! \param[in] aTest string for tested expression
//! \param[in] aFile source file name
//! \param[in] aLine source file line
//! \param[in] aMessage error message
TestRunner::TestFailed::TestFailed(const char* aTest,
                                   const char* aFile,
                                   int aLine,
                                   const std::string &aMessage)
{
    std::ostringstream assertMsg;
    assertMsg << "[" << BaseName(aFile) << ":" << aLine
              << "] Assertion failed ("
              << aTest << ") " << aMessage;
    m_message = assertMsg.str();
}

TestRunner::TestFailed::TestFailed(const std::string &message)
{
    m_message = message;
}

void TestRunner::RegisterTest(const char *testName, TestCase proc)
{
    m_testGroups[m_currentGroup].push_back(TestCaseStruct(testName, proc));
}

void TestRunner::InitGroup(const char* name)
{
    m_currentGroup = name;
}

void TestRunner::normalizeXMLTag(std::string& str, const std::string& testcase)
{
    //Add testcase if missing
    std::string::size_type pos = str.find(testcase);
    if(pos != 0)
    {
        str = testcase + "_" + str;
    }

    //dpl test runner cannot have '-' character in name so it have to be replaced
    // for TCT case to make comparision works
    std::replace(str.begin(), str.end(), '-', '_');
}

bool TestRunner::filterGroupsByXmls(const std::vector<std::string> & files)
{
    DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, XMLError)

    const std::string idPath = "/test_definition/suite/set/testcase/@id";

    bool success = true;
    std::map<std::string, bool> casesMap;

    std::string testsuite;
    if(!m_testGroups.empty())
    {
        for(TestCaseGroupMap::const_iterator cit = m_testGroups.begin(); cit != m_testGroups.end(); ++cit)
        {
            if(!cit->second.empty())
            {
                for(TestCaseStructList::const_iterator cj = cit->second.begin(); cj != cit->second.end(); ++cj)
                {
                    std::string name = cj->name;
                    std::string::size_type st = name.find('_');
                    if(st != std::string::npos)
                    {
                        name = name.substr(0, st);
                        testsuite = name;
                        break;
                    }
                }
                if(!testsuite.empty()) break;
            }
        }
    }

    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlXPathInit();

    Try
    {
        FOREACH(file, files)
        {
            xmlDocPtr doc;
            xmlXPathContextPtr xpathCtx;

            doc = xmlReadFile(file->c_str(), NULL, 0);
            if (doc == NULL) {
                ThrowMsg(XMLError, "File Problem");
            } else {
                //context
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    ThrowMsg(XMLError,
                             "Error: unable to create new XPath context\n");
                }
                xpathCtx->node = xmlDocGetRootElement(doc);
            }

            std::string result;
            xmlXPathObjectPtr xpathObject;
            //get requested node's values
            xpathObject = xmlXPathEvalExpression(BAD_CAST idPath.c_str(), xpathCtx);
            if (xpathObject == NULL)
            {
                ThrowMsg(XMLError, "XPath evaluation failure: " << idPath);
            }
            xmlNodeSetPtr nodes = xpathObject->nodesetval;
            unsigned size = (nodes) ? nodes->nodeNr : 0;
            VcoreLogD("Found %i nodes matching xpath", size);
            for(unsigned i = 0; i < size; ++i)
            {
                VcoreLogD("Type: %i", nodes->nodeTab[i]->type);
                if (nodes->nodeTab[i]->type == XML_ATTRIBUTE_NODE) {
                    xmlNodePtr curNode = nodes->nodeTab[i];
                    result = getXMLNode(curNode);
                    VcoreLogD("Result: %s", result.c_str());
                    normalizeXMLTag(result, testsuite);
                    casesMap.insert(make_pair(result, false));
                }
            }
            //Cleanup of XPath data
            xmlXPathFreeObject(xpathObject);
            xmlXPathFreeContext(xpathCtx);
            xmlFreeDoc(doc);
        }
    }
    Catch(XMLError)
    {
        VcoreLogE("Libxml error: %s", _rethrown_exception.DumpToString().c_str());
        success = false;
    }
    xmlCleanupParser();

    if(!filterByXML(casesMap))
    {
        success = false;
    }

    return success;
}

bool TestRunner::filterByXML(std::map<std::string, bool> & casesMap)
{
    FOREACH(group, m_testGroups) {
        TestCaseStructList newList;
        FOREACH(iterator, group->second)
        {
            if (casesMap.find(iterator->name) != casesMap.end()) {
                casesMap[iterator->name] = true;
                newList.push_back(*iterator);
            }
        }
        group->second = newList;
    }
    FOREACH(cs, casesMap)
    {
        if(cs->second == false)
        {
            VcoreLogE("Cannot find testcase from XML file: %s", cs->first.c_str());
            return false;
        }
    }
    return true;
}

TestRunner::Status TestRunner::RunTestCase(const TestCaseStruct& testCase)
{
    try {
        testCase.proc();
    } catch (const TestFailed &e) {
        // Simple test failure
        CollectResult(testCase.name,
                      "",
                      TestResultsCollectorBase::FailStatus::FAILED,
                      e.GetMessage());
        return FAILED;
    } catch (const Ignored &e) {
        if (m_runIgnored) {
            // Simple test have to be implemented
            CollectResult(testCase.name,
                          "",
                          TestResultsCollectorBase::FailStatus::IGNORED,
                          e.GetMessage());
        }

        return IGNORED;
    } catch (const VcoreDPL::Exception &e) {
        // DPL exception failure
        CollectResult(testCase.name,
                      "",
                      TestResultsCollectorBase::FailStatus::INTERNAL,
                      "DPL exception:" + e.GetMessage() + "\n" + e.DumpToString());

        return FAILED;
    } catch (const std::exception &) {
        // std exception failure
        CollectResult(testCase.name,
                      "",
                      TestResultsCollectorBase::FailStatus::INTERNAL,
                      "std exception");

        return FAILED;
    } catch (...) {
        // Unknown exception failure
        CollectResult(testCase.name,
                      "",
                      TestResultsCollectorBase::FailStatus::INTERNAL,
                      "unknown exception");

        return FAILED;
    }

    CollectResult(testCase.name,
                  "",
                  TestResultsCollectorBase::FailStatus::NONE);

    // Everything OK
    return PASS;
}

void TestRunner::RunTests()
{
    using namespace VcoreDPL::Colors::Text;

    Banner();

    unsigned count = 0;
    FOREACH(group, m_testGroups) {
        count += group->second.size();
    }

    std::for_each(m_collectors.begin(),
                  m_collectors.end(),
                  [count] (const TestResultsCollectors::value_type & collector)
                  {
                      collector.second->Start(count);
                  });

    fprintf(stderr, "%sFound %d testcases...%s\n", GREEN_BEGIN, count, GREEN_END);
    fprintf(stderr, "%s%s%s\n", GREEN_BEGIN, "Running tests...", GREEN_END);
    FOREACH(group, m_testGroups) {
        TestCaseStructList list = group->second;
        if (!list.empty()) {
            std::for_each(
                m_collectors.begin(),
                m_collectors.end(),
                [&group](const TestResultsCollectors::value_type & collector)
                {
                    collector.second->
                        CollectCurrentTestGroupName(group->first);
                });
            list.sort();

            for (TestCaseStructList::const_iterator iterator = list.begin();
                 iterator != list.end();
                 ++iterator)
            {
                TestCaseStruct test = *iterator;
                if (m_startTestId == test.name) {
                    m_startTestId = "";
                }

                if (m_startTestId.empty()) {
                    RunTestCase(test);
                }
                if (m_terminate == true) {
                    // Terminate quietly without any logs
                    return;
                }
            }
        }
    }

    std::for_each(m_collectors.begin(),
                  m_collectors.end(),
                  [] (const TestResultsCollectors::value_type & collector)
                  {
                      collector.second->Finish();
                  });

    // Finished
    fprintf(stderr, "%s%s%s\n\n", GREEN_BEGIN, "Finished", GREEN_END);
}

void TestRunner::CollectResult(
    const std::string& id,
    const std::string& description,
    const TestResultsCollectorBase::FailStatus::Type status,
    const std::string& reason)
{
    std::for_each(m_collectors.begin(),
                  m_collectors.end(),
                  [&](const TestResultsCollectors::value_type & collector)
                  {
                      collector.second->CollectResult(id,
                                                      description,
                                                      status,
                                                      reason);
                  });
}

void TestRunner::Banner()
{
    using namespace VcoreDPL::Colors::Text;
    fprintf(stderr,
            "%s%s%s\n",
            BOLD_GREEN_BEGIN,
            "DPL tests runner",
            BOLD_GREEN_END);
    fprintf(stderr,
            "%s%s%s%s\n\n",
            GREEN_BEGIN,
            "Build: ",
            __TIMESTAMP__,
            GREEN_END);
}

void TestRunner::InvalidArgs(const std::string& message)
{
    using namespace VcoreDPL::Colors::Text;
    fprintf(stderr,
            "%s%s%s\n",
            BOLD_RED_BEGIN,
            message.c_str(),
            BOLD_RED_END);
}

void TestRunner::Usage()
{
    fprintf(stderr, "Usage: runner [options]\n\n");
    fprintf(stderr, "Output type:\n");
    fprintf(stderr, "  --output=<output type> --output=<output type> ...\n");
    fprintf(stderr, "\n  possible output types:\n");
    FOREACH(type, TestResultsCollectorBase::GetCollectorsNames()) {
        fprintf(stderr, "    --output=%s\n", type->c_str());
    }
    fprintf(stderr, "\n  example:\n");
    fprintf(stderr,
            "    test-binary --output=text --output=xml --file=output.xml\n\n");
    fprintf(stderr, "Other parameters:\n");
    fprintf(stderr,
            "  --regexp='regexp'\t Only selected tests"
            " which names match regexp run\n\n");
    fprintf(stderr, "  --start=<test id>\tStart from concrete test id");
    fprintf(stderr, "  --group=<group name>\t Run tests only from one group\n");
    fprintf(stderr, "  --runignored\t Run also ignored tests\n");
    fprintf(stderr, "  --list\t Show a list of Test IDs\n");
    fprintf(stderr, "  --listgroups\t Show a list of Test Group names \n");
    fprintf(stderr, "  --only-from-xml=<xml file>\t Run only testcases specified in XML file \n"
                    "       XML name is taken from attribute id=\"part1_part2\" as whole.\n"
                    "       If part1 is not found (no _) then it is implicitily "
                           "set according to suite part1 from binary tests\n");
    fprintf(
        stderr,
        "  --listingroup=<group name>\t Show a list of Test IDS in one group\n");
    fprintf(stderr, "  --allowchildlogs\t Allow to print logs from child process on screen.\n");
    fprintf(stderr, "       When active child process will be able to print logs on stdout and stderr.\n");
    fprintf(stderr, "       Both descriptors will be closed after test.\n");
    fprintf(stderr, "  --help\t This help\n\n");
    std::for_each(m_collectors.begin(),
                  m_collectors.end(),
                  [] (const TestResultsCollectors::value_type & collector)
                  {
                      fprintf(stderr,
                              "Output %s has specific args:\n",
                              collector.first.c_str());
                      fprintf(stderr,
                              "%s\n",
                              collector.second->
                                  CollectorSpecificHelp().c_str());
                  });
    fprintf(stderr, "For bug reporting, please write to:\n");
    fprintf(stderr, "<p.dobrowolsk@samsung.com>\n");
}

int TestRunner::ExecTestRunner(int argc, char *argv[])
{
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        args.push_back(argv[i]);
    }
    return ExecTestRunner(args);
}

void TestRunner::MarkAssertion()
{
    ++m_totalAssertions;
}

int TestRunner::ExecTestRunner(const ArgsList& value)
{
    m_runIgnored = false;
    ArgsList args = value;
    // Parse command line
    if (args.size() == 1) {
        InvalidArgs();
        Usage();
        return -1;
    }

    args.erase(args.begin());

    bool showHelp = false;
    bool justList = false;
    std::vector<std::string> xmlFiles;

    TestResultsCollectorBasePtr currentCollector;

    // Parse each argument
    FOREACH(it, args)
    {
        std::string arg = *it;
        const std::string regexp = "--regexp=";
        const std::string output = "--output=";
        const std::string groupId = "--group=";
        const std::string runIgnored = "--runignored";
        const std::string listCmd = "--list";
        const std::string startCmd = "--start=";
        const std::string listGroupsCmd = "--listgroups";
        const std::string listInGroup = "--listingroup=";
        const std::string allowChildLogs = "--allowchildlogs";
        const std::string onlyFromXML = "--only-from-xml=";

        if (currentCollector) {
            if (currentCollector->ParseCollectorSpecificArg(arg)) {
                continue;
            }
        }

        if (arg.find(startCmd) == 0) {
            arg.erase(0, startCmd.length());
            FOREACH(group, m_testGroups) {
                FOREACH(tc, group->second) {
                    if (tc->name == arg) {
                        m_startTestId = arg;
                        break;
                    }
                }
                if (!m_startTestId.empty()) {
                    break;
                }
            }
            if (!m_startTestId.empty()) {
                continue;
            }
            InvalidArgs();
            fprintf(stderr, "Start test id has not been found\n");
            Usage();
            return 0;
        } else if (arg.find(groupId) == 0) {
            arg.erase(0, groupId.length());
            TestCaseGroupMap::iterator found = m_testGroups.find(arg);
            if (found != m_testGroups.end()) {
                std::string name = found->first;
                TestCaseStructList newList = found->second;
                m_testGroups.clear();
                m_testGroups[name] = newList;
            } else {
                fprintf(stderr, "Group %s not found\n", arg.c_str());
                InvalidArgs();
                Usage();
                return -1;
            }
        } else if (arg == runIgnored) {
            m_runIgnored = true;
        } else if (arg == listCmd) {
            justList = true;
        } else if (arg == listGroupsCmd) {
            FOREACH(group, m_testGroups) {
                printf("GR:%s\n", group->first.c_str());
            }
            return 0;
        } else if (arg.find(listInGroup) == 0) {
            arg.erase(0, listInGroup.length());
            FOREACH(test, m_testGroups[arg]) {
                printf("ID:%s\n", test->name.c_str());
            }
            return 0;
        } else if (arg.find(allowChildLogs) == 0) {
            arg.erase(0, allowChildLogs.length());
            m_allowChildLogs = true;
        } else if (arg == "--help") {
            showHelp = true;
        } else if (arg.find(output) == 0) {
            arg.erase(0, output.length());
            if (m_collectors.find(arg) != m_collectors.end()) {
                InvalidArgs(
                    "Multiple outputs of the same type are not supported!");
                Usage();
                return -1;
            }
            currentCollector.reset(TestResultsCollectorBase::Create(arg));
            if (!currentCollector) {
                InvalidArgs("Unsupported output type!");
                Usage();
                return -1;
            }
            m_collectors[arg] = currentCollector;
        } else if (arg.find(regexp) == 0) {
            arg.erase(0, regexp.length());
            if (arg.length() == 0) {
                InvalidArgs();
                Usage();
                return -1;
            }

            if (arg[0] == '\'' && arg[arg.length() - 1] == '\'') {
                arg.erase(0);
                arg.erase(arg.length() - 1);
            }

            if (arg.length() == 0) {
                InvalidArgs();
                Usage();
                return -1;
            }

            pcrecpp::RE re(arg.c_str());
            FOREACH(group, m_testGroups) {
                TestCaseStructList newList;
                FOREACH(iterator, group->second)
                {
                    if (re.PartialMatch(iterator->name)) {
                        newList.push_back(*iterator);
                    }
                }
                group->second = newList;
            }
        } else if(arg.find(onlyFromXML) == 0) {
            arg.erase(0, onlyFromXML.length());
            if (arg.length() == 0) {
                InvalidArgs();
                Usage();
                return -1;
            }

            if (arg[0] == '\'' && arg[arg.length() - 1] == '\'') {
                arg.erase(0);
                arg.erase(arg.length() - 1);
            }

            if (arg.length() == 0) {
                InvalidArgs();
                Usage();
                return -1;
            }

            xmlFiles.push_back(arg);
        } else {
            InvalidArgs();
            Usage();
            return -1;
        }
    }

    if(!xmlFiles.empty())
    {
        if(!filterGroupsByXmls(xmlFiles))
        {
            fprintf(stderr, "XML file is not correct\n");
            return 0;
        }
    }

    if(justList)
    {
        FOREACH(group, m_testGroups) {
            FOREACH(test, group->second) {
                printf("ID:%s:%s\n", group->first.c_str(), test->name.c_str());
            }
        }
        return 0;
    }

    currentCollector.reset();

    // Show help
    if (showHelp) {
        Usage();
        return 0;
    }

    if (m_collectors.empty()) {
        TestResultsCollectorBasePtr collector(
            TestResultsCollectorBase::Create("text"));
        m_collectors["text"] = collector;
    }

    for (auto it = m_collectors.begin(); it != m_collectors.end(); ++it) {
        if (!it->second->Configure()) {
            fprintf(stderr, "Could not configure selected output");
            return 0;
        }
    }

    // Run tests
    RunTests();

    return 0;
}

bool TestRunner::getRunIgnored() const
{
    return m_runIgnored;
}

void TestRunner::Terminate()
{
    m_terminate = true;
}

bool TestRunner::GetAllowChildLogs()
{
    return m_allowChildLogs;
}

}
} // namespace VcoreDPL
