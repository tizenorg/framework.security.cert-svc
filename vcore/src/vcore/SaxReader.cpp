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
#include <dpl/exception.h>
#include <dpl/log/log.h>

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

void SaxReader::initialize(const std::string &filename,
        bool defaultArgs,
        ValidationType validate,
        const std::string &schema)
{
    Assert(m_reader == 0 && "Double initialization of SaxReader");

    LogDebug("SaxReader opening file: " << filename);

    /*
     * create a new xml text reader
     */
    m_reader = xmlNewTextReaderFilename(filename.c_str());

    if (m_reader == NULL) {
        /*
         * no such file, return
         */
        LogWarning("Error during opening file " << filename);
        Throw(Exception::FileOpeningError);
    }
    if (validate == VALIDATION_XMLSCHEME &&
        xmlTextReaderSchemaValidate(m_reader, schema.c_str())) {
        /*
         * unable to turn on schema validation
         */
        LogError("Turn on Schema validation failed.");
        ThrowMsg(Exception::ParserInternalError,
                 "Turn on Scheme validation failed!");
    }
    // Path to DTD schema is taken from xml file.
    if (validate == VALIDATION_DTD &&
        xmlTextReaderSetParserProp(m_reader, XML_PARSER_VALIDATE, 1)) {
        /*
         * unable to turn on DTD validation
         */
        LogError("Turn on DTD validation failed!");
        ThrowMsg(Exception::ParserInternalError,
                 "Turn on DTD validation failed!");
    }
    if (defaultArgs &&
        xmlTextReaderSetParserProp(m_reader, XML_PARSER_DEFAULTATTRS, 1)) {
        /*
         * unable to turn on default arguments
         */
        LogError("Turn on default arguments failed");
        ThrowMsg(Exception::ParserInternalError,
                 "Turn on Default Arguments failed!");
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

    if (0 == xmlTextReaderIsValid(m_reader)) {
        LogWarning("Throw exception file not valid!");
        Throw(Exception::FileNotValid);
    }

    if (res == 1) {
        return true;
    }

    if (res == 0) {
        return false;
    }
    LogError("ParserInternalError");
    Throw(Exception::ParserInternalError);
}

void SaxReader::next(const std::string &token)
{
    xmlTextReaderRead(m_reader);
    if (0 == xmlTextReaderIsValid(m_reader)) {
        /*
         * invalid file
         */
        LogWarning("Throw exception file not valid!");
        Throw(Exception::FileNotValid);
    }

    xmlChar *name = xmlTextReaderName(m_reader);

    if (name == NULL) {
        /*
         * invalid file
         */
        LogWarning("File not Valid");
        Throw(Exception::FileNotValid);
    }

    if (token == reinterpret_cast<const char*>(name)) {
        xmlFree(name);
    } else {
        /*
         * we encountered wrong token
         */
        xmlFree(name);
        LogWarning("Wrong Token");
        Throw(Exception::WrongToken);
    }
}

bool SaxReader::isEmpty(void)
{
    int ret = xmlTextReaderIsEmptyElement(m_reader);
    if (-1 == ret) {
        LogError("Parser Internal Error");
        Throw(Exception::ParserInternalErrorInEmptyQuery);
    }
    return ret;
}

std::string SaxReader::attribute(const std::string &token,
        ThrowType throwStatus)
{
    std::string value;
    xmlChar *attr = xmlTextReaderGetAttribute(m_reader, BAD_CAST(token.c_str()));
    if ((NULL == attr) && (throwStatus == THROW_DISABLE)) {
        /*
         * return empty string
         */
        //TODO why not DPL::Optional?
        return std::string();
    }
    if (NULL == attr) {
        /*
         * error during read attribute
         */
        LogError("Error in reading attribute.");
        Throw(Exception::ParserInternalErrorInReadingAttribute);
    }

    /*
     * cast it to val and return it
     */
    value = reinterpret_cast<const char *>(attr);
    xmlFree(attr);
    return value;
}

// KW std::string SaxReader::fullName(){
// KW     std::string value;
// KW     xmlChar *name = xmlTextReaderName(m_reader);
// KW     if(NULL == name) {
// KW         LogError("Error in reading name.");
// KW         Throw(Exception::ErrorReadingName);
// KW     }
// KW     value = reinterpret_cast<const char *>(name);
// KW     xmlFree(name);
// KW     return value;
// KW }

std::string SaxReader::name()
{
    std::string value;
    xmlChar *name = xmlTextReaderName(m_reader);
    if (NULL == name) {
        LogError("Error in reading name.");
        Throw(Exception::ErrorReadingName);
    }
    value = reinterpret_cast<const char *>(name);
    xmlFree(name);
    size_t pos = value.find_last_of(":");
    if (pos != std::string::npos) {
        value.erase(0, pos + 1);
    }
    return value;
}

std::string SaxReader::namespaceURI()
{
    std::string value;
    xmlChar *name = xmlTextReaderNamespaceUri(m_reader);
    if (NULL != name) {
        value = reinterpret_cast<const char *>(name);
        xmlFree(name);
    }
    return value;
}

std::string SaxReader::value()
{
    std::string value;
    /*
     * get value of node
     */
    xmlChar *text = xmlTextReaderValue(m_reader);
    if (NULL == text) {
        LogError("Error in reading value");
        Throw(Exception::ErrorReadingValue);
    }
    value = reinterpret_cast<const char*>(text);
    /*
     * free text and return the val
     */
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
    /*
     * size of buffer
     */
    int size;
    /*
     * pointer to buffer
     */
    xmlBufferPtr buff = xmlBufferCreate();

    xmlNodePtr node = xmlTextReaderExpand(m_reader);

    if (node == NULL) {
        /*
         * internal parser error
         */
        xmlBufferFree(buff);
        LogError("Parser Internal Error");
        Throw(Exception::ParserInternalError);
    }

    /*
     * get a size and fill in a buffer
     */
    size = xmlNodeDump(buff, node->doc, node, 0, 0);
    buffer.insert(0, reinterpret_cast<char*>(buff->content), size);
    xmlBufferFree(buff);
}
} // namespace ValidationCore
