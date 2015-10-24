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
 * @file        SaxReader.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Simple c++ interface for libxml2.
 */
#include <dpl/assert.h>
#include <dpl/log/wrt_log.h>

#include <vcore/SaxReader.h>

namespace ValidationCore {


SaxReader::SaxReader() :
    m_reader(0)
{
}

SaxReader::~SaxReader()
{
    if (m_reader) {
        deinitialize();
    }
}

void SaxReader::initialize(
    const std::string &filename,
    bool defaultArgs,
    ValidationType validate,
    const std::string &schema)
{
    Assert(m_reader == 0 && "Double initialization of SaxReader");

    WrtLogD("SaxReader opening file: %s", filename.c_str());

    m_reader = xmlNewTextReaderFilename(filename.c_str());

    if (!m_reader) {
        VcoreThrowMsg(SaxReader::Exception::FileOpeningError,
                      "opening file " << filename << " error");
    }

    if (validate == VALIDATION_XMLSCHEME &&
        xmlTextReaderSchemaValidate(m_reader, schema.c_str())) {
        /*
         * unable to turn on schema validation
         */
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "Turn on Schema validation failed");
    }

    // Path to DTD schema is taken from xml file.
    if (validate == VALIDATION_DTD &&
        xmlTextReaderSetParserProp(m_reader, XML_PARSER_VALIDATE, 1)) {
        /*
         * unable to turn on DTD validation
         */
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
		              "Turn on DTD validation failed!");
    }

    if (defaultArgs &&
        xmlTextReaderSetParserProp(m_reader, XML_PARSER_DEFAULTATTRS, 1)) {
        /*
         * unable to turn on default arguments
         */
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
		              "Turn on default arguments failed");
    }
}

void SaxReader::deinitialize()
{
    xmlFreeTextReader(m_reader);
    m_reader = 0;
}

bool SaxReader::next()
{
    int res = xmlTextReaderRead(m_reader);

    if (res < 0)
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "xmlTextReaderRead error");

    if (!xmlTextReaderIsValid(m_reader))
        VcoreThrowMsg(SaxReader::Exception::FileNotValid,
                      "xmlTextReader is invalid");

    return res ? true : false;
}

void SaxReader::next(const std::string &token)
{
    int res = xmlTextReaderRead(m_reader);

    if (res < 0)
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "xmlTextReaderRead error");

    if (!xmlTextReaderIsValid(m_reader))
        VcoreThrowMsg(SaxReader::Exception::FileNotValid,
                      "xmlTextReader is invalid");

    xmlChar *name = xmlTextReaderName(m_reader);

    if (!name)
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "xmlTextReaderName returns NULL");

    xmlChar *xmlToken = xmlCharStrdup(token.c_str());

    if (xmlStrcmp(name, xmlToken)) {
        xmlFree(name);
        xmlFree(xmlToken);

        VcoreThrowMsg(SaxReader::Exception::WrongToken, "Wrong Token");
    }

    xmlFree(name);
    xmlFree(xmlToken);
}

bool SaxReader::isEmpty(void)
{
    int ret = xmlTextReaderIsEmptyElement(m_reader);
    if (-1 == ret)
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "xmlTextReaderIsEmptyElement error");

    return ret ? true : false;
}

std::string SaxReader::attribute(const std::string &token, ThrowType throwStatus)
{
    xmlChar *attr = xmlTextReaderGetAttribute(m_reader, BAD_CAST(token.c_str()));
    if (!attr) {
        if (throwStatus == THROW_DISABLE) {
            return std::string();
        }
        else {
            VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                          "xmlTextReaderGetAttribute error");
        }
    }

    std::string value = reinterpret_cast<const char *>(attr);
    xmlFree(attr);

    return value;
}

std::string SaxReader::name()
{
    xmlChar *name = xmlTextReaderName(m_reader);
    if (!name)
        VcoreThrowMsg(SaxReader::Exception::ReadingNameError,
                      "reading name error");

    std::string value = reinterpret_cast<const char *>(name);
    xmlFree(name);
    size_t pos = value.find_last_of(":");
    if (pos != std::string::npos) {
        value.erase(0, pos + 1);
    }

    return value;
}

std::string SaxReader::namespaceURI()
{
    xmlChar *name = xmlTextReaderNamespaceUri(m_reader);
    if (!name) {
        return std::string();
    }

    std::string value = reinterpret_cast<const char *>(name);
    xmlFree(name);

    return value;
}

std::string SaxReader::value()
{
    xmlChar *text = xmlTextReaderValue(m_reader);
    if (!text)
        VcoreThrowMsg(SaxReader::Exception::ReadingValueError,
                      "reading value error");

    std::string value = reinterpret_cast<const char*>(text);
    xmlFree(text);

    return value;
}

SaxReader::NodeType SaxReader::type()
{
    xmlReaderTypes type =
        static_cast<xmlReaderTypes>(xmlTextReaderNodeType(m_reader));
    switch (type) {
    case XML_READER_TYPE_ELEMENT:
        return NODE_BEGIN;
    case XML_READER_TYPE_END_ELEMENT:
        return NODE_END;
    case XML_READER_TYPE_TEXT:
        return NODE_TEXT;
    case XML_READER_TYPE_NONE:
    case XML_READER_TYPE_ATTRIBUTE:
    case XML_READER_TYPE_CDATA:
    case XML_READER_TYPE_ENTITY_REFERENCE:
    case XML_READER_TYPE_ENTITY:
    case XML_READER_TYPE_PROCESSING_INSTRUCTION:
    case XML_READER_TYPE_COMMENT:
    case XML_READER_TYPE_DOCUMENT:
    case XML_READER_TYPE_DOCUMENT_TYPE:
    case XML_READER_TYPE_DOCUMENT_FRAGMENT:
    case XML_READER_TYPE_NOTATION:
    case XML_READER_TYPE_WHITESPACE:
    case XML_READER_TYPE_SIGNIFICANT_WHITESPACE:
    case XML_READER_TYPE_END_ENTITY:
    case XML_READER_TYPE_XML_DECLARATION:
    default:
        return NODE_UNSUPPORTED;
    }
}

void SaxReader::dumpNode(std::string &buffer)
{
    xmlBufferPtr buff = xmlBufferCreate();

    xmlNodePtr node = xmlTextReaderExpand(m_reader);
    if (!node) {
        xmlBufferFree(buff);
        VcoreThrowMsg(SaxReader::Exception::ParserInternalError,
                      "xmlTextReaderExpand error");
    }

    int size = xmlNodeDump(buff, node->doc, node, 0, 0);
    if (size > 0) {
        buffer.insert(0, reinterpret_cast<char*>(buff->content), size);
    }
    xmlBufferFree(buff);
}

} // namespace ValidationCore
