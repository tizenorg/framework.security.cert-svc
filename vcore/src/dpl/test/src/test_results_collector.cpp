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
 * @brief       Implementation file some concrete TestResulstsCollector
 */
#include <cstddef>
#include <dpl/test/test_results_collector.h>
#include <dpl/colors.h>
#include <dpl/assert.h>
#include <dpl/foreach.h>
#include <dpl/scoped_fclose.h>
#include <dpl/exception.h>
#include <dpl/errno_string.h>
#include <dpl/lexical_cast.h>
#include <dpl/availability.h>

#include <string>
#include <string.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <cstdlib>

#define GREEN_RESULT_OK "[%s%s%s]\n", BOLD_GREEN_BEGIN, "   OK   ", \
    BOLD_GREEN_END

namespace VcoreDPL {
namespace Test {
namespace {
const char *DEFAULT_HTML_FILE_NAME = "index.html";
const char *DEFAULT_TAP_FILE_NAME = "results.tap";
const char *DEFAULT_XML_FILE_NAME = "results.xml";

bool ParseCollectorFileArg(const std::string &arg, std::string &filename)
{
    const std::string argname = "--file=";
    if (arg.find(argname) == 0 ) {
        filename = arg.substr(argname.size());
        return true;
    }
    return false;
}

class Statistic
{
  public:
    Statistic() :
        m_failed(0),
        m_ignored(0),
        m_passed(0),
        m_count(0)
    {}

    void AddTest(TestResultsCollectorBase::FailStatus::Type type)
    {
        ++m_count;
        switch (type) {
        case TestResultsCollectorBase::FailStatus::INTERNAL:
        case TestResultsCollectorBase::FailStatus::FAILED:   ++m_failed;
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED:  ++m_ignored;
            break;
        case TestResultsCollectorBase::FailStatus::NONE:     ++m_passed;
            break;
        default:
            Assert(false && "Bad FailStatus");
        }
    }

    std::size_t GetTotal() const
    {
        return m_count;
    }
    std::size_t GetPassed() const
    {
        return m_passed;
    }
    std::size_t GetSuccesed() const
    {
        return m_passed;
    }
    std::size_t GetFailed() const
    {
        return m_failed;
    }
    std::size_t GetIgnored() const
    {
        return m_ignored;
    }
    float GetPassedOrIgnoredPercend() const
    {
        float passIgnoredPercent =
            100.0f * (static_cast<float>(m_passed)
                      + static_cast<float>(m_ignored))
            / static_cast<float>(m_count);
        return passIgnoredPercent;
    }

  private:
    std::size_t m_failed;
    std::size_t m_ignored;
    std::size_t m_passed;
    std::size_t m_count;
};

class ConsoleCollector :
    public TestResultsCollectorBase
{
  public:
    static TestResultsCollectorBase* Constructor();

  private:
    ConsoleCollector() {}

    virtual void CollectCurrentTestGroupName(const std::string& name)
    {
        printf("Starting group %s\n", name.c_str());
        m_currentGroup = name;
    }

    virtual void Finish()
    {
        using namespace VcoreDPL::Colors::Text;

        // Show result
        FOREACH(group, m_groupsStats) {
            PrintStats(group->first, group->second);
        }
        PrintStats("All tests together", m_stats);
    }

    virtual void CollectResult(const std::string& id,
                               const std::string& /*description*/,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "")
    {
        using namespace VcoreDPL::Colors::Text;
        std::string tmp = "'" + id + "' ...";

        printf("Running test case %-60s", tmp.c_str());
        switch (status) {
        case TestResultsCollectorBase::FailStatus::NONE:
            printf(GREEN_RESULT_OK);
            break;
        case TestResultsCollectorBase::FailStatus::FAILED:
            PrintfErrorMessage(" FAILED ", reason, true);
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED:
            PrintfIgnoredMessage("Ignored ", reason, true);
            break;
        case TestResultsCollectorBase::FailStatus::INTERNAL:
            PrintfErrorMessage("INTERNAL", reason, true);
            break;
        default:
            Assert(false && "Bad status");
        }
        m_stats.AddTest(status);
        m_groupsStats[m_currentGroup].AddTest(status);
    }

    void PrintfErrorMessage(const char* type,
                            const std::string& message,
                            bool verbosity)
    {
        using namespace VcoreDPL::Colors::Text;
        if (verbosity) {
            printf("[%s%s%s] %s%s%s\n",
                   BOLD_RED_BEGIN,
                   type,
                   BOLD_RED_END,
                   BOLD_YELLOW_BEGIN,
                   message.c_str(),
                   BOLD_YELLOW_END);
        } else {
            printf("[%s%s%s]\n",
                   BOLD_RED_BEGIN,
                   type,
                   BOLD_RED_END);
        }
    }

    void PrintfIgnoredMessage(const char* type,
                              const std::string& message,
                              bool verbosity)
    {
        using namespace VcoreDPL::Colors::Text;
        if (verbosity) {
            printf("[%s%s%s] %s%s%s\n",
                   CYAN_BEGIN,
                   type,
                   CYAN_END,
                   BOLD_GOLD_BEGIN,
                   message.c_str(),
                   BOLD_GOLD_END);
        } else {
            printf("[%s%s%s]\n",
                   CYAN_BEGIN,
                   type,
                   CYAN_END);
        }
    }

    void PrintStats(const std::string& title, const Statistic& stats)
    {
        using namespace VcoreDPL::Colors::Text;
        printf("\n%sResults [%s]: %s\n", BOLD_GREEN_BEGIN,
               title.c_str(), BOLD_GREEN_END);
        printf("%s%s%3d%s\n",
               CYAN_BEGIN,
               "Total tests:            ",
               stats.GetTotal(),
               CYAN_END);
        printf("  %s%s%3d%s\n",
               CYAN_BEGIN,
               "Succeeded:            ",
               stats.GetPassed(),
               CYAN_END);
        printf("  %s%s%3d%s\n",
               CYAN_BEGIN,
               "Failed:               ",
               stats.GetFailed(),
               CYAN_END);
        printf("  %s%s%3d%s\n",
               CYAN_BEGIN,
               "Ignored:              ",
               stats.GetIgnored(),
               CYAN_END);
    }

    Statistic m_stats;
    std::map<std::string, Statistic> m_groupsStats;
    std::string m_currentGroup;
};

TestResultsCollectorBase* ConsoleCollector::Constructor()
{
    return new ConsoleCollector();
}

class HtmlCollector :
    public TestResultsCollectorBase
{
  public:
    static TestResultsCollectorBase* Constructor();

  private:
    HtmlCollector() : m_filename(DEFAULT_HTML_FILE_NAME) {}

    virtual void CollectCurrentTestGroupName(const std::string& name)
    {
        fprintf(m_fp.Get(), "<b>Starting group %s", name.c_str());
        m_currentGroup = name;
    }

    virtual bool Configure()
    {
        m_fp.Reset(fopen(m_filename.c_str(), "w"));
        if (!m_fp) {
            VcoreLogD("Could not open file %s for writing", m_filename.c_str());
            return false;
        }
        return true;
    }
    virtual std::string CollectorSpecificHelp() const
    {
        return "--file=<filename> - name of file for output\n"
               "                    default - index.html\n";
    }

    virtual void Start(int count)
    {
        DPL_UNUSED_PARAM(count);
        AssertMsg(!!m_fp, "File handle must not be null");
        fprintf(m_fp.Get(),
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0"
                "Transitional//EN\" "
                "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\""
                ">\n");
        fprintf(m_fp.Get(),
                "<html xmlns=\"http://www.w3.org/1999/xhtml\" "
                "lang=\"en\" dir=\"ltr\">\n");
        fprintf(m_fp.Get(), "<body style=\"background-color: black;\">\n");
        fprintf(m_fp.Get(), "<pre>\n");
        fprintf(m_fp.Get(), "<font color=\"white\">\n");
    }

    virtual void Finish()
    {
        using namespace VcoreDPL::Colors::Html;
        // Show result
        FOREACH(group, m_groupsStats) {
            PrintStats(group->first, group->second);
        }
        PrintStats("All tests together", m_stats);
        fprintf(m_fp.Get(), "</font>\n");
        fprintf(m_fp.Get(), "</pre>\n");
        fprintf(m_fp.Get(), "</body>\n");
        fprintf(m_fp.Get(), "</html>\n");
    }

    virtual bool ParseCollectorSpecificArg(const std::string& arg)
    {
        return ParseCollectorFileArg(arg, m_filename);
    }

    virtual void CollectResult(const std::string& id,
                               const std::string& /*description*/,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "")
    {
        using namespace VcoreDPL::Colors::Html;
        std::string tmp = "'" + id + "' ...";

        fprintf(m_fp.Get(), "Running test case %-100s", tmp.c_str());
        switch (status) {
        case TestResultsCollectorBase::FailStatus::NONE:
            fprintf(m_fp.Get(), GREEN_RESULT_OK);
            break;
        case TestResultsCollectorBase::FailStatus::FAILED:
            PrintfErrorMessage(" FAILED ", reason, true);
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED:
            PrintfIgnoredMessage("Ignored ", reason, true);
            break;
        case TestResultsCollectorBase::FailStatus::INTERNAL:
            PrintfErrorMessage("INTERNAL", reason, true);
            break;
        default:
            Assert(false && "Bad status");
        }
        m_groupsStats[m_currentGroup].AddTest(status);
        m_stats.AddTest(status);
    }

    void PrintfErrorMessage(const char* type,
                            const std::string& message,
                            bool verbosity)
    {
        using namespace VcoreDPL::Colors::Html;
        if (verbosity) {
            fprintf(m_fp.Get(),
                    "[%s%s%s] %s%s%s\n",
                    BOLD_RED_BEGIN,
                    type,
                    BOLD_RED_END,
                    BOLD_YELLOW_BEGIN,
                    message.c_str(),
                    BOLD_YELLOW_END);
        } else {
            fprintf(m_fp.Get(),
                    "[%s%s%s]\n",
                    BOLD_RED_BEGIN,
                    type,
                    BOLD_RED_END);
        }
    }

    void PrintfIgnoredMessage(const char* type,
                              const std::string& message,
                              bool verbosity)
    {
        using namespace VcoreDPL::Colors::Html;

        if (verbosity) {
            fprintf(m_fp.Get(),
                    "[%s%s%s] %s%s%s\n",
                    CYAN_BEGIN,
                    type,
                    CYAN_END,
                    BOLD_GOLD_BEGIN,
                    message.c_str(),
                    BOLD_GOLD_END);
        } else {
            fprintf(m_fp.Get(),
                    "[%s%s%s]\n",
                    CYAN_BEGIN,
                    type,
                    CYAN_END);
        }
    }

    void PrintStats(const std::string& name, const Statistic& stats)
    {
        using namespace VcoreDPL::Colors::Html;
        fprintf(
            m_fp.Get(), "\n%sResults [%s]:%s\n", BOLD_GREEN_BEGIN,
            name.c_str(), BOLD_GREEN_END);
        fprintf(
            m_fp.Get(), "%s%s%3d%s\n", CYAN_BEGIN,
            "Total tests:            ", stats.GetTotal(), CYAN_END);
        fprintf(
            m_fp.Get(), "  %s%s%3d%s\n", CYAN_BEGIN,
            "Succeeded:            ", stats.GetPassed(), CYAN_END);
        fprintf(
            m_fp.Get(), "  %s%s%3d%s\n", CYAN_BEGIN,
            "Failed:               ", stats.GetFailed(), CYAN_END);
        fprintf(
            m_fp.Get(), "  %s%s%3d%s\n", CYAN_BEGIN,
            "Ignored:              ", stats.GetIgnored(), CYAN_END);
    }

    std::string m_filename;
    ScopedFClose m_fp;
    Statistic m_stats;
    std::string m_currentGroup;
    std::map<std::string, Statistic> m_groupsStats;
};

TestResultsCollectorBase* HtmlCollector::Constructor()
{
    return new HtmlCollector();
}

class XmlCollector :
    public TestResultsCollectorBase
{
  public:
    static TestResultsCollectorBase* Constructor();

  private:
    XmlCollector() : m_filename(DEFAULT_XML_FILE_NAME) {}

    virtual void CollectCurrentTestGroupName(const std::string& name)
    {
        std::size_t pos = GetCurrentGroupPosition();
        if (std::string::npos != pos) {
            GroupFinish(pos);
            FlushOutput();
            m_stats = Statistic();
        }

        pos = m_outputBuffer.find("</testsuites>");
        if (std::string::npos == pos) {
            ThrowMsg(VcoreDPL::Exception, "Could not find test suites closing tag");
        }
        GroupStart(pos, name);
    }

    void GroupStart(const std::size_t pos, const std::string& name)
    {
        std::stringstream groupHeader;
        groupHeader << "\n\t<testsuite";
        groupHeader << " name=\"" << EscapeSpecialCharacters(name) << "\"";
        groupHeader << R"( tests="1")"; // include SegFault
        groupHeader << R"( failures="1")"; // include SegFault
        groupHeader << R"( skipped="0")";
        groupHeader << ">";

        groupHeader << "\n\t\t<testcase name=\"unknown\" status=\"FAILED\">";
        groupHeader <<
        "\n\t\t\t<failure type=\"FAILED\" message=\"segmentation fault\"/>";
        groupHeader << "\n\t\t</testcase>";

        groupHeader << "\n\t</testsuite>";

        m_outputBuffer.insert(pos - 1, groupHeader.str());
    }

    virtual bool Configure()
    {
        m_fp.Reset(fopen(m_filename.c_str(), "w"));
        if (!m_fp) {
            VcoreLogD("Could not open file %s for writing", m_filename.c_str());
            return false;
        }
        return true;
    }

    virtual std::string CollectorSpecificHelp() const
    {
        return "--file=<filename> - name of file for output\n"
               "                    default - results.xml\n";
    }

    virtual void Start(int count)
    {
        AssertMsg(!!m_fp, "File handle must not be null");
        m_outputBuffer.append("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
        m_outputBuffer.append("<testsuites ");
        if(count >= 0)
        {
            m_outputBuffer.append("total=\"");
            m_outputBuffer.append(VcoreDPL::lexical_cast<std::string>(count));
            m_outputBuffer.append("\"");
        }
        m_outputBuffer.append(" >\n</testsuites>");
        FlushOutput();
    }

    virtual void Finish()
    {
        std::size_t pos = GetCurrentGroupPosition();
        if (std::string::npos != pos) {
            GroupFinish(pos);
            FlushOutput();
        }
    }

    virtual bool ParseCollectorSpecificArg(const std::string& arg)
    {
        return ParseCollectorFileArg(arg, m_filename);
    }

    virtual void CollectResult(const std::string& id,
                               const std::string& /*description*/,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "")
    {
        m_resultBuffer.erase();
        m_resultBuffer.append("\t\t<testcase name=\"");
        m_resultBuffer.append(EscapeSpecialCharacters(id));
        m_resultBuffer.append("\"");
        switch (status) {
        case TestResultsCollectorBase::FailStatus::NONE:
            m_resultBuffer.append(" status=\"OK\"/>\n");
            break;
        case TestResultsCollectorBase::FailStatus::FAILED:
            m_resultBuffer.append(" status=\"FAILED\">\n");
            PrintfErrorMessage("FAILED", EscapeSpecialCharacters(reason), true);
            m_resultBuffer.append("\t\t</testcase>\n");
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED:
            m_resultBuffer.append(" status=\"Ignored\">\n");
            PrintfIgnoredMessage("Ignored", EscapeSpecialCharacters(
                                     reason), true);
            m_resultBuffer.append("\t\t</testcase>\n");
            break;
        case TestResultsCollectorBase::FailStatus::INTERNAL:
            m_resultBuffer.append(" status=\"FAILED\">\n");
            PrintfErrorMessage("INTERNAL", EscapeSpecialCharacters(
                                   reason), true);
            m_resultBuffer.append("\t\t</testcase>");
            break;
        default:
            Assert(false && "Bad status");
        }
        std::size_t group_pos = GetCurrentGroupPosition();
        if (std::string::npos == group_pos) {
            ThrowMsg(VcoreDPL::Exception, "No current group set");
        }

        std::size_t last_case_pos = m_outputBuffer.find(
                "<testcase name=\"unknown\"",
                group_pos);
        if (std::string::npos == last_case_pos) {
            ThrowMsg(VcoreDPL::Exception, "Could not find SegFault test case");
        }
        m_outputBuffer.insert(last_case_pos - 2, m_resultBuffer);

        m_stats.AddTest(status);

        UpdateGroupHeader(group_pos,
                          m_stats.GetTotal() + 1, // include SegFault
                          m_stats.GetFailed() + 1, // include SegFault
                          m_stats.GetIgnored());
        FlushOutput();
    }

    std::size_t GetCurrentGroupPosition() const
    {
        return m_outputBuffer.rfind("<testsuite ");
    }

    void UpdateGroupHeader(const std::size_t groupPosition,
                           const unsigned int tests,
                           const unsigned int failures,
                           const unsigned int skipped)
    {
        UpdateElementAttribute(groupPosition, "tests", UIntToString(tests));
        UpdateElementAttribute(groupPosition, "failures", UIntToString(failures));
        UpdateElementAttribute(groupPosition, "skipped", UIntToString(skipped));
    }

    void UpdateElementAttribute(const std::size_t elementPosition,
                                const std::string& name,
                                const std::string& value)
    {
        std::string pattern = name + "=\"";

        std::size_t start = m_outputBuffer.find(pattern, elementPosition);
        if (std::string::npos == start) {
            ThrowMsg(VcoreDPL::Exception,
                     "Could not find attribute " << name << " beginning");
        }

        std::size_t end = m_outputBuffer.find("\"", start + pattern.length());
        if (std::string::npos == end) {
            ThrowMsg(VcoreDPL::Exception,
                     "Could not find attribute " << name << " end");
        }

        m_outputBuffer.replace(start + pattern.length(),
                               end - start - pattern.length(),
                               value);
    }

    std::string UIntToString(const unsigned int value)
    {
        std::stringstream result;
        result << value;
        return result.str();
    }

    void GroupFinish(const std::size_t groupPosition)
    {
        std::size_t segFaultStart =
            m_outputBuffer.find("<testcase name=\"unknown\"", groupPosition);
        if (std::string::npos == segFaultStart) {
            ThrowMsg(VcoreDPL::Exception,
                     "Could not find SegFault test case start position");
        }
        segFaultStart -= 2; // to erase tabs

        std::string closeTag = "</testcase>";
        std::size_t segFaultEnd = m_outputBuffer.find(closeTag, segFaultStart);
        if (std::string::npos == segFaultEnd) {
            ThrowMsg(VcoreDPL::Exception,
                     "Could not find SegFault test case end position");
        }
        segFaultEnd += closeTag.length() + 1; // to erase new line

        m_outputBuffer.erase(segFaultStart, segFaultEnd - segFaultStart);

        UpdateGroupHeader(groupPosition,
                          m_stats.GetTotal(),
                          m_stats.GetFailed(),
                          m_stats.GetIgnored());
    }

    void FlushOutput()
    {
        int fd = fileno(m_fp.Get());
        if (-1 == fd) {
            int error = errno;
            ThrowMsg(VcoreDPL::Exception, VcoreDPL::GetErrnoString(error));
        }

        if (-1 == TEMP_FAILURE_RETRY(ftruncate(fd, 0L))) {
            int error = errno;
            ThrowMsg(VcoreDPL::Exception, VcoreDPL::GetErrnoString(error));
        }

        if (-1 == TEMP_FAILURE_RETRY(fseek(m_fp.Get(), 0L, SEEK_SET))) {
            int error = errno;
            ThrowMsg(VcoreDPL::Exception, VcoreDPL::GetErrnoString(error));
        }

        if (m_outputBuffer.size() !=
            fwrite(m_outputBuffer.c_str(), 1, m_outputBuffer.size(),
                   m_fp.Get()))
        {
            int error = errno;
            ThrowMsg(VcoreDPL::Exception, VcoreDPL::GetErrnoString(error));
        }

        if (-1 == TEMP_FAILURE_RETRY(fflush(m_fp.Get()))) {
            int error = errno;
            ThrowMsg(VcoreDPL::Exception, VcoreDPL::GetErrnoString(error));
        }
    }

    void PrintfErrorMessage(const char* type,
                            const std::string& message,
                            bool verbosity)
    {
        if (verbosity) {
            m_resultBuffer.append("\t\t\t<failure type=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(type));
            m_resultBuffer.append("\" message=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(message));
            m_resultBuffer.append("\"/>\n");
        } else {
            m_resultBuffer.append("\t\t\t<failure type=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(type));
            m_resultBuffer.append("\"/>\n");
        }
    }

    void PrintfIgnoredMessage(const char* type,
                              const std::string& message,
                              bool verbosity)
    {
        if (verbosity) {
            m_resultBuffer.append("\t\t\t<skipped type=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(type));
            m_resultBuffer.append("\" message=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(message));
            m_resultBuffer.append("\"/>\n");
        } else {
            m_resultBuffer.append("\t\t\t<skipped type=\"");
            m_resultBuffer.append(EscapeSpecialCharacters(type));
            m_resultBuffer.append("\"/>\n");
        }
    }

    std::string EscapeSpecialCharacters(std::string s)
    {
        for (unsigned int i = 0; i < s.size();) {
            switch (s[i]) {
            case '"':
                s.erase(i, 1);
                s.insert(i, "&quot;");
                i += 6;
                break;

            case '&':
                s.erase(i, 1);
                s.insert(i, "&amp;");
                i += 5;
                break;

            case '<':
                s.erase(i, 1);
                s.insert(i, "&lt;");
                i += 4;
                break;

            case '>':
                s.erase(i, 1);
                s.insert(i, "&gt;");
                i += 4;
                break;

            case '\'':
                s.erase(i, 1);
                s.insert(i, "&#39;");
                i += 5;
                break;
            default:
                ++i;
                break;
            }
        }
        return s;
    }

    std::string m_filename;
    ScopedFClose m_fp;
    Statistic m_stats;
    std::string m_outputBuffer;
    std::string m_resultBuffer;
};

TestResultsCollectorBase* XmlCollector::Constructor()
{
    return new XmlCollector();
}

class CSVCollector :
    public TestResultsCollectorBase
{
  public:
    static TestResultsCollectorBase* Constructor();

  private:
    CSVCollector() {}

    virtual void Start(int count)
    {
        DPL_UNUSED_PARAM(count);
        printf("GROUP;ID;RESULT;REASON\n");
    }

    virtual void CollectCurrentTestGroupName(const std::string& name)
    {
        m_currentGroup = name;
    }

    virtual void CollectResult(const std::string& id,
                               const std::string& /*description*/,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "")
    {
        std::string statusMsg = "";
        switch (status) {
        case TestResultsCollectorBase::FailStatus::NONE: statusMsg = "OK";
            break;
        case TestResultsCollectorBase::FailStatus::FAILED: statusMsg = "FAILED";
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED: statusMsg =
            "IGNORED";
            break;
        case TestResultsCollectorBase::FailStatus::INTERNAL: statusMsg =
            "FAILED";
            break;
        default:
            Assert(false && "Bad status");
        }
        printf("%s;%s;%s;%s\n",
               m_currentGroup.c_str(),
               id.c_str(),
               statusMsg.c_str(),
               reason.c_str());
    }

    std::string m_currentGroup;
};

TestResultsCollectorBase* CSVCollector::Constructor()
{
    return new CSVCollector();
}
}

class TAPCollector :
    public TestResultsCollectorBase
{
  public:
    static TestResultsCollectorBase* Constructor();

  private:
    TAPCollector() : m_filename(DEFAULT_TAP_FILE_NAME)  {}

    virtual bool Configure()
    {
        m_output.open(m_filename.c_str(), std::ios_base::trunc);
        if (m_output.fail()) {
            VcoreLogE("Can't open output file: %s", m_filename.c_str());
            return false;
        }
        return true;
    }
    virtual std::string CollectorSpecificHelp() const
    {
        std::string retVal = "--file=<filename> - name of file for output\n"
                             "                    default - ";
        retVal += DEFAULT_TAP_FILE_NAME;
        retVal += "\n";
        return retVal;
    }

    virtual void Start(int count)
    {
        DPL_UNUSED_PARAM(count);
        AssertMsg(m_output.good(), "Output file must be opened.");
        m_output << "TAP version 13" << std::endl;
        m_testIndex = 0;
    }

    virtual void Finish()
    {
        m_output << "1.." << m_testIndex << std::endl;
        m_output << m_collectedData.rdbuf();
        m_output.close();
    }

    virtual bool ParseCollectorSpecificArg(const std::string& arg)
    {
        return ParseCollectorFileArg(arg, m_filename);
    }

    virtual void CollectResult(const std::string& id,
                               const std::string& description,
                               const FailStatus::Type status = FailStatus::NONE,
                               const std::string& reason = "")
    {
        m_testIndex++;
        switch (status) {
        case TestResultsCollectorBase::FailStatus::NONE:
            LogBasicTAP(true, id, description);
            endTAPLine();
            break;
        case TestResultsCollectorBase::FailStatus::FAILED:
            LogBasicTAP(false, id, description);
            endTAPLine();
            break;
        case TestResultsCollectorBase::FailStatus::IGNORED:
            LogBasicTAP(true, id, description);
            m_collectedData << " # skip " << reason;
            endTAPLine();
            break;
        case TestResultsCollectorBase::FailStatus::INTERNAL:
            LogBasicTAP(true, id, description);
            endTAPLine();
            m_collectedData << "    ---" << std::endl;
            m_collectedData << "    message: " << reason << std::endl;
            m_collectedData << "    severity: Internal" << std::endl;
            m_collectedData << "    ..." << std::endl;
            break;
        default:
            Assert(false && "Bad status");
        }
    }

    void LogBasicTAP(bool isOK, const std::string& id,
                     const std::string& description)
    {
        if (!isOK) {
            m_collectedData << "not ";
        }
        m_collectedData << "ok " << m_testIndex << " [" <<
        id << "] " << description;
    }

    void endTAPLine()
    {
        m_collectedData << std::endl;
    }

    std::string m_filename;
    std::stringstream m_collectedData;
    std::ofstream m_output;
    int m_testIndex;
};

TestResultsCollectorBase* TAPCollector::Constructor()
{
    return new TAPCollector();
}

void TestResultsCollectorBase::RegisterCollectorConstructor(
    const std::string& name,
    TestResultsCollectorBase::CollectorConstructorFunc func)
{
    Assert(m_constructorsMap.find(name) == m_constructorsMap.end());
    m_constructorsMap[name] = func;
}

TestResultsCollectorBase* TestResultsCollectorBase::Create(
    const std::string& name)
{
    ConstructorsMap::iterator found = m_constructorsMap.find(name);
    if (found != m_constructorsMap.end()) {
        return found->second();
    } else {
        return NULL;
    }
}

std::vector<std::string> TestResultsCollectorBase::GetCollectorsNames()
{
    std::vector<std::string> list;
    FOREACH(it, m_constructorsMap)
    {
        list.push_back(it->first);
    }
    return list;
}

TestResultsCollectorBase::ConstructorsMap TestResultsCollectorBase::
    m_constructorsMap;

namespace {
static int RegisterCollectorConstructors();
static const int RegisterHelperVariable = RegisterCollectorConstructors();
int RegisterCollectorConstructors()
{
    (void)RegisterHelperVariable;

    TestResultsCollectorBase::RegisterCollectorConstructor(
        "text",
        &ConsoleCollector::Constructor);
    TestResultsCollectorBase::RegisterCollectorConstructor(
        "html",
        &HtmlCollector::Constructor);
    TestResultsCollectorBase::RegisterCollectorConstructor(
        "csv",
        &CSVCollector::Constructor);
    TestResultsCollectorBase::RegisterCollectorConstructor(
        "tap",
        &TAPCollector::Constructor);
    TestResultsCollectorBase::RegisterCollectorConstructor(
        "xml",
        &XmlCollector::Constructor);

    return 0;
}
}
}
}
#undef GREEN_RESULT_OK
