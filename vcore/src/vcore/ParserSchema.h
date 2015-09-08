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
 * @file        ParserSchema.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _PARSERSCHEMA_H_
#define _PARSERSCHEMA_H_

#include <map>
#include <string>

#include <vcore/SaxReader.h>
#include <vcore/exception.h>

namespace ValidationCore {
namespace ParserSchemaException {
    VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base);
    VCORE_DECLARE_EXCEPTION_TYPE(Base, XmlReaderError);
    VCORE_DECLARE_EXCEPTION_TYPE(Base, CertificateLoaderError);
    VCORE_DECLARE_EXCEPTION_TYPE(Base, UnsupportedAlgorithm);
    VCORE_DECLARE_EXCEPTION_TYPE(Base, UnsupportedValue);
}

template<typename ParserType, typename DataType>
class ParserSchema {
public:

    struct TagDescription {
        TagDescription(const std::string &tag,
                const std::string & xmlNamespace) :
            tagName(tag),
            namespaceUri(xmlNamespace)
        {
        }

        std::string tagName;
        std::string namespaceUri;

        bool operator<(const TagDescription &second) const
        {
            if (tagName < second.tagName) {
                return true;
            }
            if (tagName > second.tagName) {
                return false;
            }
            if (namespaceUri < second.namespaceUri) {
                return true;
            }
            return false;
        }
    };


    ParserSchema(ParserType *parser)
      : m_functions(parser) {}

    virtual ~ParserSchema() {}

    void initialize(
            const std::string &filename,
            bool defaultArgs,
            SaxReader::ValidationType valType,
            const std::string &xmlschema)
    {
        VcoreTry
        {
            m_reader.initialize(filename, defaultArgs, valType, xmlschema);
        }
        VcoreCatch (SaxReader::Exception::Base)
        {
            VcoreReThrowMsg(ParserSchemaException::XmlReaderError, "XmlReaderError");
        }
    }

    void deinitialize()
    {
        m_reader.deinitialize();
    }

    void read(DataType &dataContainer)
    {
        VcoreTry
        {
            while (m_reader.next()) {
                switch (m_reader.type()) {
                case SaxReader::NODE_BEGIN:
                    beginNode(dataContainer);
                    break;
                case SaxReader::NODE_END:
                    endNode(dataContainer);
                    break;
                case SaxReader::NODE_TEXT:
                    textNode(dataContainer);
                    break;
                default:
                    break;
                }
            }
        }
        VcoreCatch (SaxReader::Exception::Base)
        {
            VcoreReThrowMsg(ParserSchemaException::XmlReaderError, "XmlReaderError");
        }
    }

    typedef void (ParserType::*FunctionPtr)(DataType &data);
    typedef std::map<TagDescription, FunctionPtr> FunctionMap;

    void addBeginTagCallback(
            const std::string &tag,
            const std::string &namespaceUri,
            FunctionPtr function)
    {
        TagDescription desc(tag, namespaceUri);
        m_beginFunctionMap[desc] = function;
    }

    void addEndTagCallback(
            const std::string &tag,
            const std::string &namespaceUri,
            FunctionPtr function)
    {
        TagDescription desc(tag, namespaceUri);
        m_endFunctionMap[desc] = function;
    }

    SaxReader& getReader()
    {
        return m_reader;
    }

    std::string& getText()
    {
        return m_textNode;
    }

protected:
    void beginNode(DataType &dataContainer)
    {
        TagDescription desc(m_reader.name(), m_reader.namespaceURI());
        FunctionPtr fun = m_beginFunctionMap[desc];

        if (fun == 0) {
            return;
        }

        (m_functions->*fun)(dataContainer);
    }

    void endNode(DataType &dataContainer)
    {
        TagDescription desc(m_reader.name(), m_reader.namespaceURI());
        FunctionPtr fun = m_endFunctionMap[desc];

        if (fun == 0) {
            return;
        }

        (m_functions->*fun)(dataContainer);
    }

    void textNode(DataType &dataContainer)
    {
        (void)dataContainer;
        m_textNode = m_reader.value();
    }

    ParserType *m_functions;
    SaxReader m_reader;
    FunctionMap m_beginFunctionMap;
    FunctionMap m_endFunctionMap;

    // temporary values require due parsing textNode
    std::string m_textNode;
};

} // namespace ValidationCore
#endif
