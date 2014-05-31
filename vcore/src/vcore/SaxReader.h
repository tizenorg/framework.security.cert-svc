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
 * @file        SaxReader.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Simple c++ interface for libxml2.
 *              Its used in wrt-installer only and should be removed
 *              from cert-svc.
 */
#ifndef _SAXREADER_H_
#define _SAXREADER_H_

#include <string>
#include <libxml/xmlreader.h>
#include <dpl/exception.h>

namespace ValidationCore {
class SaxReader
{
  public:
    SaxReader();
    ~SaxReader();

    /*
     * custom exceptions
     */
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, FileOpeningError)
        DECLARE_EXCEPTION_TYPE(Base, FileNotValid)
        DECLARE_EXCEPTION_TYPE(Base, ParserInternalError)
        DECLARE_EXCEPTION_TYPE(Base, WrongToken)
        DECLARE_EXCEPTION_TYPE(Base, ParserInternalErrorInReadingAttribute)
        DECLARE_EXCEPTION_TYPE(Base, ParserInternalErrorInEmptyQuery)
        DECLARE_EXCEPTION_TYPE(Base, ErrorReadingValue)
        DECLARE_EXCEPTION_TYPE(Base, ErrorReadingName)
        DECLARE_EXCEPTION_TYPE(Base, UnsupportedType)
    };

    enum NodeType
    {
        NODE_UNSUPPORTED,
        NODE_BEGIN,
        NODE_END,
        NODE_TEXT
    };

    enum ThrowType
    {
        THROW_ENABLE = 0,
        THROW_DISABLE
    };

    /*
     * xml validation modes
     */
    enum ValidationType
    {
        VALIDATION_DISABLE,
        VALIDATION_XMLSCHEME,
        VALIDATION_DTD
    };

    /*
     * initializes parser
     */
    void initialize(const std::string &filename,
            bool defaultArgs = false,
            ValidationType validation = VALIDATION_DISABLE,
            const std::string &schema = std::string());
    /*
     * deinitializes parser
     */
    void deinitialize();

    /**
     * Move to next xml node.
     */
    bool next();

    /**
     * Move to next xml node. If next node name is differ from token the exception will
     * be thrown.
     */
    void next(const std::string &token);

    /**
     * Check if xml tag is empty.
     */
    bool isEmpty(void);

    /**
     * Read attribute tag.
     */
    std::string attribute(const std::string &token,
            ThrowType throwStatus = THROW_ENABLE);

    /**
     * Read xml tag name with namespace.
     */
    // KW    std::string fullName();

    /**
     * Read xml tag name without namespace.
     */
    std::string name();

    /**
     * Read xml tag namespace URI
     */
    std::string namespaceURI();

    /**
     * Read xml tag value.
     */
    std::string value();

    /**
     * Return information about node type.
     */
    NodeType type();

    /**
     * Save all contonet of xml file which is between current tag and
     * it's close tag into buffer.
     */
    void dumpNode(std::string &buffer);

  private:
    /*
     * internal libxml text reader
     */
    xmlTextReaderPtr m_reader;
};
}

#endif // _SAXREADER_H_
