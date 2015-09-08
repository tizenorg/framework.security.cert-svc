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
 * @file        orm.h
 * @author      Bartosz Janiak (b.janiak@samsung.com)
 * @version     1.0
 * @brief       DPL-ORM: Object-relational mapping for sqlite database, written on top of DPL.
 */

#include <cstdlib>
#include <cstdio>
#include <string>
#include <typeinfo>
#include <utility>
#include <set>
#include <list>
#include <memory>
#include <boost/optional.hpp>

#include <dpl/db/sql_connection.h>
#include <dpl/db/orm_interface.h>
#include <dpl/string.h>
#include <dpl/type_list.h>
#include <dpl/assert.h>
#include <dpl/foreach.h>

#ifndef DPL_ORM_H
#define DPL_ORM_H

namespace VcoreDPL {
namespace DB {
namespace ORM {

//TODO move to type utils
#define DPL_CHECK_TYPE_INSTANTIABILITY(type) \
    { \
        type _ignored_; \
        (void)_ignored_; \
    }

#define DECLARE_COLUMN_TYPE_LIST() typedef VcoreDPL::TypeListDecl<
#define SELECTED_COLUMN(table_name, column_name) table_name::column_name,
#define DECLARE_COLUMN_TYPE_LIST_END(name) VcoreDPL::TypeListGuard>::Type name;

typedef size_t ColumnIndex;
typedef size_t ArgumentIndex;
typedef boost::optional<VcoreDPL::String> OptionalString;
typedef boost::optional<int> OptionalInteger;
typedef VcoreDPL::DB::SqlConnection::DataCommand DataCommand;

namespace RelationTypes {
    extern const char Equal[];
    extern const char LessThan[];
    extern const char And[];
    extern const char Or[];
    extern const char Is[];
    extern const char In[];
    //TODO define more relation types
}

namespace DataCommandUtils {
    //TODO move to VcoreDPL::DataCommand?
    void BindArgument(DataCommand *command, ArgumentIndex index, int argument);
    void BindArgument(DataCommand *command, ArgumentIndex index, const OptionalInteger& argument);
    void BindArgument(DataCommand *command, ArgumentIndex index, const VcoreDPL::String& argument);
    void BindArgument(DataCommand *command, ArgumentIndex index, const OptionalString& argument);
}
class __attribute__ ((visibility("hidden"))) Expression {
public:
    virtual ~Expression() {}
    virtual std::string GetString() const = 0;
    virtual ArgumentIndex BindTo(DataCommand *command, ArgumentIndex index) = 0;
};

typedef std::shared_ptr<Expression> ExpressionPtr;

namespace OrderingUtils {

template<typename CompoundType> inline std::string OrderByInternal()
{
    std::string order = OrderByInternal<typename CompoundType::Tail>();
    if(!order.empty()) return CompoundType::Head::GetString() + ", " + order;
    else return CompoundType::Head::GetString();
}

template<> inline std::string OrderByInternal<TypeListGuard>()
{
    return std::string();
}

}

template<typename ColumnType>
class __attribute__ ((visibility("hidden"))) OrderingExpression {
protected:
    static std::string GetSchemaAndName()
    {
        std::string statement;
        statement += ColumnType::GetTableName();
        statement += ".";
        statement += ColumnType::GetColumnName();
        statement += " ";
        return statement;
    }
public:
    virtual ~OrderingExpression() {}
};

template<const char* Operator, typename LeftExpression, typename RightExpression>
class __attribute__ ((visibility("hidden"))) BinaryExpression : public Expression {
protected:
    LeftExpression  m_leftExpression;
    RightExpression m_rightExpression;
    bool            m_outerParenthesis;
public:
    BinaryExpression(const LeftExpression& leftExpression, const RightExpression& rightExpression, bool outerParenthesis = true) :
        m_leftExpression(leftExpression),
        m_rightExpression(rightExpression),
        m_outerParenthesis(outerParenthesis)
    {}

    virtual std::string GetString() const
    {
        return  (m_outerParenthesis ? "( " : " " ) +
                 m_leftExpression.GetString() + " " + Operator + " " + m_rightExpression.GetString() +
                (m_outerParenthesis ? " )" : " " ) ;
    }

    virtual ArgumentIndex BindTo(DataCommand *command, ArgumentIndex index)
    {
        index = m_leftExpression.BindTo(command, index);
        return  m_rightExpression.BindTo(command, index);
    }

    template<typename TableDefinition>
    struct ValidForTable {
        typedef std::pair<typename LeftExpression ::template ValidForTable<TableDefinition>::Yes ,
                          typename RightExpression::template ValidForTable<TableDefinition>::Yes >
                Yes;
    };
};

template<typename LeftExpression, typename RightExpression>
BinaryExpression<RelationTypes::And, LeftExpression, RightExpression>
    And(const LeftExpression& leftExpression, const RightExpression& rightExpression)
{
    return BinaryExpression<RelationTypes::And, LeftExpression, RightExpression>
            (leftExpression, rightExpression);
}

template<typename LeftExpression, typename RightExpression>
BinaryExpression<RelationTypes::Or, LeftExpression, RightExpression>
    Or(const LeftExpression& leftExpression, const RightExpression& rightExpression)
{
    return BinaryExpression<RelationTypes::Or, LeftExpression, RightExpression>
            (leftExpression, rightExpression);
}

template<typename ArgumentType>
class __attribute__ ((visibility("hidden"))) ExpressionWithArgument : public Expression {
protected:
    ArgumentType argument;

public:
    explicit ExpressionWithArgument(const ArgumentType& _argument) : argument(_argument) {}

    virtual ArgumentIndex BindTo(DataCommand *command, ArgumentIndex index)
    {
        DataCommandUtils::BindArgument(command, index, argument);
        return index + 1;
    }
};

template<typename ColumnData, const char* Relation>
class __attribute__ ((visibility("hidden"))) Compare : public ExpressionWithArgument<typename ColumnData::ColumnType> {
public:
    explicit Compare(typename ColumnData::ColumnType column) :
        ExpressionWithArgument<typename ColumnData::ColumnType>(column)
    {}

    virtual std::string GetString() const
    {
        std::string statement;
        statement += ColumnData::GetTableName();
        statement += ".";
        statement += ColumnData::GetColumnName();
        statement += " ";
        statement += Relation;
        statement += " ?";
        return statement;
    }

    template<typename TableDefinition>
    struct ValidForTable {
        typedef typename TableDefinition::ColumnList::template Contains<ColumnData> Yes;
    };
};
#define ORM_DEFINE_COMPARE_EXPRESSION(name, relationType)                      \
    template<typename ColumnData>                                              \
    class __attribute__ ((visibility("hidden"))) name : public Compare<ColumnData, RelationTypes::relationType> {     \
    public:                                                                    \
        name(typename ColumnData::ColumnType column) :                         \
            Compare<ColumnData, RelationTypes::relationType>(column)           \
        {}                                                                     \
    };

ORM_DEFINE_COMPARE_EXPRESSION(Equals, Equal)
ORM_DEFINE_COMPARE_EXPRESSION(Is, Is)

#define ORM_DEFINE_ORDERING_EXPRESSION(name, value)                                     \
    template<typename ColumnType>                                                       \
    class __attribute__ ((visibility("hidden"))) name                                   \
        : OrderingExpression<ColumnType> {                                              \
    public:                                                                             \
        static std::string GetString()                                                  \
        {                                                                               \
            std::string statement = OrderingExpression<ColumnType>::GetSchemaAndName(); \
            statement += value;                                                         \
            return statement;                                                           \
        }                                                                               \
    };

ORM_DEFINE_ORDERING_EXPRESSION(OrderingAscending, "ASC")
ORM_DEFINE_ORDERING_EXPRESSION(OrderingDescending, "DESC")

template<typename ColumnData1, typename ColumnData2>
class __attribute__ ((visibility("hidden"))) CompareBinaryColumn {
private:
    std::string m_relation;
public:
    CompareBinaryColumn(const char* Relation) :
      m_relation(Relation)
    {}

    virtual ~CompareBinaryColumn() {}

    virtual std::string GetString() const
    {
        std::string statement;
        statement += ColumnData1::GetTableName();
        statement += ".";
        statement += ColumnData1::GetColumnName();
        statement += " ";
        statement += m_relation;
        statement += " ";
        statement += ColumnData2::GetTableName();
        statement += ".";
        statement += ColumnData2::GetColumnName();

        return statement;
    }
};

template<typename ColumnData1, typename ColumnData2>
CompareBinaryColumn<ColumnData1, ColumnData2>
    Equal()
{
    return CompareBinaryColumn<ColumnData1, ColumnData2>(RelationTypes::Equal);
}

template<typename ColumnData, const char* Relation>
class __attribute__ ((visibility("hidden"))) NumerousArguments : public Expression {
protected:
    std::set<typename ColumnData::ColumnType> m_argumentList;
public:
    NumerousArguments(const std::set<typename ColumnData::ColumnType>& argumentList) : m_argumentList(argumentList) {}

    virtual std::string GetString() const
    {
        std::string statement;
        statement += ColumnData::GetColumnName();
        statement += " ";
        statement += Relation;
        statement += " ( ";

        int argumentCount = m_argumentList.size();
        while(argumentCount)
        {
            statement += "?";
            argumentCount--;
            if (argumentCount)
            {
                statement += ", ";
            }
        }

        statement += " )";

        return statement;
    }

    virtual ArgumentIndex BindTo(DataCommand *command, ArgumentIndex index)
    {
        ArgumentIndex argumentIndex = index;
        FOREACH(argumentIt, m_argumentList)
        {
            DataCommandUtils::BindArgument(command, argumentIndex, *argumentIt);
            argumentIndex++;
        }
        return  argumentIndex + 1;
    }

    template<typename TableDefinition>
    struct ValidForTable {
        typedef typename TableDefinition::ColumnList::template Contains<ColumnData> Yes;
    };
};

#define ORM_DEFINE_COMPARE_EXPRESSION_NUMEROUS_ARGUMENTS(name, relationType)                      \
    template<typename ColumnData>                                              \
    class __attribute__ ((visibility("hidden"))) name : public NumerousArguments<ColumnData, RelationTypes::relationType> {     \
    public:                                                                    \
        name(std::set<typename ColumnData::ColumnType> column) :                         \
            NumerousArguments<ColumnData, RelationTypes::relationType>(column)           \
        {}                                                                     \
    };

ORM_DEFINE_COMPARE_EXPRESSION_NUMEROUS_ARGUMENTS(In, In)

template<typename ColumnType>
ColumnType GetColumnFromCommand(ColumnIndex columnIndex, DataCommand *command);

class __attribute__ ((visibility("hidden"))) CustomColumnBase {
public:
    CustomColumnBase() {}
    virtual ~CustomColumnBase() {}
};

template<typename ColumnType>
class __attribute__ ((visibility("hidden"))) CustomColumn : public CustomColumnBase {
private:
    ColumnType m_columnData;

public:
    CustomColumn() {}
    CustomColumn(ColumnType data)
    {
        m_columnData = data;
    }

    void SetColumnData(ColumnType data)
    {
        m_columnData = data;
    }

    ColumnType GetColumnData() const
    {
        return m_columnData;
    }
};

template<typename ColumnList>
class __attribute__ ((visibility("hidden"))) CustomRowUtil {
public:
    static void MakeColumnList(std::vector<CustomColumnBase*>& columnList)
    {
        typedef CustomColumn<typename ColumnList::Head::ColumnType> Type;
        Type* pColumn = new Type();
        columnList.push_back(pColumn);
        CustomRowUtil<typename ColumnList::Tail>::MakeColumnList(columnList);
    }

    static void CopyColumnList(const std::vector<CustomColumnBase*>& srcList, std::vector<CustomColumnBase*>& dstList)
    {
        CopyColumnList(srcList, dstList, 0);
    }

    static ColumnIndex GetColumnIndex(const std::string& columnName)
    {
        return GetColumnIndex(columnName, 0);
    }

private:
    static void CopyColumnList(const std::vector<CustomColumnBase*>& srcList, std::vector<CustomColumnBase*>& dstList, ColumnIndex index)
    {
        typedef CustomColumn<typename ColumnList::Head::ColumnType> Type;
        Type* pColumn = new Type(((Type*)(srcList.at(index)))->GetColumnData());
        dstList.push_back(pColumn);
        CustomRowUtil<typename ColumnList::Tail>::CopyColumnList(srcList, dstList, index + 1);
    }

    static ColumnIndex GetColumnIndex(const std::string& columnName, ColumnIndex index)
    {
        if (ColumnList::Head::GetColumnName() == columnName)
            return index;

        return CustomRowUtil<typename ColumnList::Tail>::GetColumnIndex(columnName, index + 1);
    }

template<typename Other>
friend class CustomRowUtil;
};

template<>
class __attribute__ ((visibility("hidden"))) CustomRowUtil<VcoreDPL::TypeListGuard> {
public:
    static void MakeColumnList(std::vector<CustomColumnBase*>&) {}
private:
    static void CopyColumnList(const std::vector<CustomColumnBase*>&, std::vector<CustomColumnBase*>&, ColumnIndex) {}
    static ColumnIndex GetColumnIndex(const std::string&, ColumnIndex) { return -1; }

template<typename Other>
friend class CustomRowUtil;
};

template<typename ColumnList>
class __attribute__ ((visibility("hidden"))) CustomRow {
private:
    std::vector<CustomColumnBase*> m_columns;

public:
    CustomRow()
    {
        CustomRowUtil<ColumnList>::MakeColumnList(m_columns);
    }

    CustomRow(const CustomRow& r)
    {
        CustomRowUtil<ColumnList>::CopyColumnList(r.m_columns, m_columns);
    }

    virtual ~CustomRow()
    {
        while (!m_columns.empty())
        {
            CustomColumnBase* pCustomColumn = m_columns.back();
            m_columns.pop_back();
            if (pCustomColumn)
                delete pCustomColumn;
        }
    }

    template<typename ColumnType>
    void SetColumnData(ColumnIndex columnIndex, ColumnType data)
    {
        typedef CustomColumn<ColumnType> Type;
        Assert(columnIndex < m_columns.size());
        Type* pColumn = dynamic_cast<Type*>(m_columns.at(columnIndex));
        Assert(pColumn);
        pColumn->SetColumnData(data);
    }

    template<typename ColumnData>
    typename ColumnData::ColumnType GetColumnData()
    {
        typedef CustomColumn<typename ColumnData::ColumnType> Type;
        ColumnIndex index = CustomRowUtil<ColumnList>::GetColumnIndex(ColumnData::GetColumnName());
        Assert(index < m_columns.size());
        Type* pColumn = dynamic_cast<Type*>(m_columns.at(index));
        Assert(pColumn);
        return pColumn->GetColumnData();
    }
};

template<typename CustomRow, typename ColumnType>
void SetColumnData(CustomRow& row, ColumnType columnData, ColumnIndex columnIndex)
{
    row.SetColumnData<ColumnType>(columnIndex, columnData);
}

template<typename ColumnList, typename CustomRow>
class  __attribute__ ((visibility("hidden"))) FillCustomRowUtil {
public:
    static void FillCustomRow(CustomRow& row, DataCommand* command)
    {
        FillCustomRow(row, 0, command);
    }

private:
    static void FillCustomRow(CustomRow& row, ColumnIndex columnIndex, DataCommand* command)
    {
        typename ColumnList::Head::ColumnType columnData;
        columnData = GetColumnFromCommand<typename ColumnList::Head::ColumnType>(columnIndex, command);
        SetColumnData<CustomRow, typename ColumnList::Head::ColumnType>(row, columnData, columnIndex);
        FillCustomRowUtil<typename ColumnList::Tail, CustomRow>::FillCustomRow(row, columnIndex + 1, command);
    }

template<typename Other, typename OtherRow>
friend class FillCustomRowUtil;
};

template<typename CustomRow>
class  __attribute__ ((visibility("hidden"))) FillCustomRowUtil<VcoreDPL::TypeListGuard, CustomRow> {
private:
    static void FillCustomRow(CustomRow&, ColumnIndex, DataCommand *)
    { /* do nothing, we're past the last element of column list */ }

template<typename Other, typename OtherRow>
friend class FillCustomRowUtil;
};

template<typename ColumnList, typename Row>
class  __attribute__ ((visibility("hidden"))) FillRowUtil {
public:
    static void FillRow(Row& row, DataCommand *command)
    {
        FillRow(row, 0, command);
    }

private:
    static void FillRow(Row& row, ColumnIndex columnIndex, DataCommand *command)
    {
        typename ColumnList::Head::ColumnType rowField;
        rowField = GetColumnFromCommand<typename ColumnList::Head::ColumnType>(columnIndex, command);
        ColumnList::Head::SetRowField(row, rowField);
        FillRowUtil<typename ColumnList::Tail, Row>::FillRow(row, columnIndex + 1, command);
    }

template<typename Other, typename OtherRow>
friend class FillRowUtil;
};

template<typename Row>
class  __attribute__ ((visibility("hidden"))) FillRowUtil<VcoreDPL::TypeListGuard, Row> {
private:
    static void FillRow(Row&, ColumnIndex, DataCommand *)
    { /* do nothing, we're past the last element of column list */ }

template<typename Other, typename OtherRow>
friend class FillRowUtil;
};

template<typename ColumnList>
class  __attribute__ ((visibility("hidden"))) JoinUtil {
public:
    static std::string GetColumnNames()
    {
        std::string result;
        result = ColumnList::Head::GetTableName();
        result += ".";
        result += ColumnList::Head::GetColumnName();
        if (ColumnList::Tail::Size > 0)
            result += ", ";

        return result += JoinUtil<typename ColumnList::Tail>::GetColumnNames();
    }

    static std::string GetJoinTableName(const std::string& tableName)
    {
        std::string joinTableName = ColumnList::Head::GetTableName();
        if (tableName.find(joinTableName) == std::string::npos)
            return joinTableName;

        return JoinUtil<typename ColumnList::Tail>::GetJoinTableName(tableName);
    }
};

template<>
class  __attribute__ ((visibility("hidden"))) JoinUtil<VcoreDPL::TypeListGuard> {
public:
    static std::string GetColumnNames() { return ""; }
    static std::string GetJoinTableName(std::string) { return ""; }
};

class Exception {
public:
    DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, SelectReuseWithDifferentQuerySignature)
    DECLARE_EXCEPTION_TYPE(Base, RowFieldNotInitialized)
    DECLARE_EXCEPTION_TYPE(Base, EmptyUpdateStatement)
};

template<typename TableDefinition>
class  __attribute__ ((visibility("hidden"))) Query
{
protected:
    explicit Query(IOrmInterface* interface) :
        m_interface(interface),
        m_command(NULL)
    {
    }

    virtual ~Query()
    {
        if (m_command == NULL)
            return;

        TableDefinition::FreeTableDataCommand(m_command, m_interface);
    }

    IOrmInterface* m_interface;
    DataCommand *m_command;
    std::string m_commandString;
    ArgumentIndex m_bindArgumentIndex;
};

template<typename TableDefinition>
class  __attribute__ ((visibility("hidden"))) QueryWithWhereClause : public Query<TableDefinition>
{
protected:
    ExpressionPtr m_whereExpression;

    void Prepare()
    {
        if ( !!m_whereExpression )
        {
            this->m_commandString += " WHERE ";
            this->m_commandString += m_whereExpression->GetString();
        }
    }

    void Bind()
    {
        if ( !!m_whereExpression )
        {
            this->m_bindArgumentIndex = m_whereExpression->BindTo(
                this->m_command, this->m_bindArgumentIndex);
        }
    }

public:
    explicit QueryWithWhereClause(IOrmInterface* interface) :
        Query<TableDefinition>(interface)
    {
    }

    template<typename Expression>
    void Where(const Expression& expression)
    {
        DPL_CHECK_TYPE_INSTANTIABILITY(typename Expression::template ValidForTable<TableDefinition>::Yes);
        if ( !!m_whereExpression && ( typeid(Expression) != typeid(*m_whereExpression) ) )
        {
            std::ostringstream str;
            str << "Current ORM implementation doesn't allow to reuse Select"
                    " instance with different query signature (particularly "
                    "WHERE on different column).\n";
            str << "Query: ";
            str << this->m_commandString;
            ThrowMsg(Exception::SelectReuseWithDifferentQuerySignature,
                str.str());
        }
        //TODO maybe don't make a copy here but just generate the string part of the query.
        m_whereExpression.reset(new Expression(expression));
    }

};

template<typename TableDefinition>
class  __attribute__ ((visibility("hidden"))) Delete : public QueryWithWhereClause<TableDefinition>
{
protected:
    void Prepare()
    {
        if ( !this->m_command)
        {
            this->m_commandString  = "DELETE FROM ";
            this->m_commandString += TableDefinition::GetName();

            QueryWithWhereClause<TableDefinition>::Prepare();

            this->m_command = TableDefinition::AllocTableDataCommand(
                    this->m_commandString.c_str(),
                    Query<TableDefinition>::m_interface);
            VcoreLogD("Prepared SQL command %s", this->m_commandString.c_str());
        }
    }

    void Bind()
    {
        this->m_bindArgumentIndex = 1;
        QueryWithWhereClause<TableDefinition>::Bind();
    }

public:
    explicit Delete(IOrmInterface *interface = NULL) :
        QueryWithWhereClause<TableDefinition>(interface)
    {
    }

    void Execute()
    {
        Prepare();
        Bind();
        this->m_command->Step();
        this->m_command->Reset();
    }
};

namespace {
class BindVisitor {
private:
    DataCommand *m_command;
public:
    ArgumentIndex m_bindArgumentIndex;

    BindVisitor(DataCommand *command) :
        m_command(command),
        m_bindArgumentIndex(1)
    {}

    template<typename ColumnType>
    void Visit(const char*, const ColumnType& value, bool isSet)
    {
        if ( isSet )
        {
            DataCommandUtils::BindArgument(m_command, m_bindArgumentIndex, value);
            m_bindArgumentIndex++;
        }
    }
};
} //anonymous namespace
template<typename TableDefinition>
class __attribute__ ((visibility("hidden"))) Insert : public Query<TableDefinition>
{
public:
    typedef typename TableDefinition::Row Row;
    typedef VcoreDPL::DB::SqlConnection::RowID RowID;

protected:
    boost::optional<std::string> m_orClause;
    Row m_row;

    class PrepareVisitor {
    public:
        std::string m_columnNames;
        std::string m_values;

        template<typename ColumnType>
        void Visit(const char* name, const ColumnType&, bool isSet)
        {
            if ( isSet )
            {
                if ( !m_columnNames.empty() )
                {
                    m_columnNames += ", ";
                    m_values += ", ";
                }
                m_columnNames += name;
                m_values += "?";
            }
        }
    };

    void Prepare()
    {
        if ( !this->m_command )
        {
            this->m_commandString = "INSERT ";
            if ( !!m_orClause )
            {
                this->m_commandString += " OR " + *m_orClause + " ";
            }
            this->m_commandString += "INTO ";
            this->m_commandString += TableDefinition::GetName();

            PrepareVisitor visitor;
            m_row.VisitColumns(visitor);

            this->m_commandString += " ( " + visitor.m_columnNames + " ) ";
            this->m_commandString += "VALUES ( " + visitor.m_values + " )";

            VcoreLogD("Prepared SQL command %s", this->m_commandString.c_str());
            this->m_command = TableDefinition::AllocTableDataCommand(
                this->m_commandString.c_str(),
                Query<TableDefinition>::m_interface);
        }
    }

    void Bind()
    {
        BindVisitor visitor(this->m_command);
        m_row.VisitColumns(visitor);
    }

public:
    explicit Insert(
            IOrmInterface* interface = NULL,
            const boost::optional<std::string>& orClause = boost::optional<std::string>()) :
        Query<TableDefinition>(interface),
        m_orClause(orClause)
    {
    }

    void Values(const Row& row)
    {
        if ( this->m_command )
        {
            if ( !row.IsSignatureMatching(m_row) )
            {
                ThrowMsg(Exception::SelectReuseWithDifferentQuerySignature,
                    "Current ORM implementation doesn't allow to reuse Insert instance "
                    "with different query signature.");
            }
        }
        m_row = row;
    }

    RowID Execute()
    {
        Prepare();
        Bind();
        this->m_command->Step();

        RowID result = TableDefinition::GetLastInsertRowID(
            Query<TableDefinition>::m_interface);

        this->m_command->Reset();
        return result;
    }
};

template<typename TableDefinition>
class __attribute__ ((visibility("hidden"))) Select : public QueryWithWhereClause<TableDefinition>
{
public:
    typedef typename TableDefinition::ColumnList       ColumnList;
    typedef typename TableDefinition::Row              Row;

    typedef std::list<Row>                             RowList;
protected:
    boost::optional<std::string> m_orderBy;
    std::string m_JoinClause;
    bool                       m_distinctResults;

    void Prepare(const char* selectColumnName)
    {
        if ( !this->m_command )
        {
            this->m_commandString  = "SELECT ";
            if (m_distinctResults)
                this->m_commandString += "DISTINCT ";
            this->m_commandString += selectColumnName;
            this->m_commandString += " FROM ";
            this->m_commandString += TableDefinition::GetName();

            this->m_commandString += m_JoinClause;

            QueryWithWhereClause<TableDefinition>::Prepare();

            if ( !!m_orderBy )
            {
                this->m_commandString += " ORDER BY " + *m_orderBy;
            }

            this->m_command = TableDefinition::AllocTableDataCommand(
                this->m_commandString.c_str(),
                Query<TableDefinition>::m_interface);

            VcoreLogD("Prepared SQL command %s", this->m_commandString.c_str());
        }
    }

    void Bind()
    {
        this->m_bindArgumentIndex = 1;
        QueryWithWhereClause<TableDefinition>::Bind();
    }

    template<typename ColumnType>
    ColumnType GetColumn(ColumnIndex columnIndex)
    {
        return GetColumnFromCommand<ColumnType>(columnIndex, this->m_command);
    }

    Row GetRow()
    {
        Row row;
        FillRowUtil<ColumnList, Row>::FillRow(row, this->m_command);
        return row;
    }

    template<typename ColumnList, typename CustomRow>
    CustomRow GetCustomRow()
    {
        CustomRow row;
        FillCustomRowUtil<ColumnList, CustomRow>::FillCustomRow(row, this->m_command);
        return row;
    }

public:

    explicit Select(IOrmInterface *interface = NULL) :
        QueryWithWhereClause<TableDefinition>(interface),
        m_distinctResults(false)
    {
    }

    void Distinct()
    {
        m_distinctResults = true;
    }

    template<typename CompoundType>
    void OrderBy(const CompoundType&)
    {
        m_orderBy = OrderingUtils::OrderByInternal<typename CompoundType::Type>();
    }

    void OrderBy(const std::string & orderBy) //backward compatibility
    {
        m_orderBy = orderBy;
    }

    void OrderBy(const char * orderBy) //backward compatibility
    {
        m_orderBy = std::string(orderBy);
    }

    template<typename ColumnList, typename Expression>
    void Join(const Expression& expression) {
        std::string usedTableNames = TableDefinition::GetName();
        if (!m_JoinClause.empty())
            usedTableNames += m_JoinClause;

        this->m_JoinClause += " JOIN ";
        this->m_JoinClause += JoinUtil<ColumnList>::GetJoinTableName(usedTableNames);
        this->m_JoinClause += " ON ";
        this->m_JoinClause += expression.GetString();
    }

    template<typename ColumnData>
    typename ColumnData::ColumnType GetSingleValue()
    {
        Prepare(ColumnData::GetColumnName());
        Bind();
        this->m_command->Step();

        typename ColumnData::ColumnType result =
            GetColumn<typename ColumnData::ColumnType>(0);

        this->m_command->Reset();
        return result;
    }

    //TODO return range - pair of custom iterators
    template<typename ColumnData>
    std::list<typename ColumnData::ColumnType> GetValueList()
    {
        Prepare(ColumnData::GetColumnName());
        Bind();

        std::list<typename ColumnData::ColumnType> resultList;

        while (this->m_command->Step())
            resultList.push_back(GetColumn<typename ColumnData::ColumnType>(0));

        this->m_command->Reset();
        return resultList;
    }

    Row GetSingleRow()
    {
        Prepare("*");
        Bind();
        this->m_command->Step();

        Row result = GetRow();

        this->m_command->Reset();
        return result;
    }

    //TODO return range - pair of custom iterators
    RowList GetRowList()
    {
        Prepare("*");
        Bind();

        RowList resultList;

        while (this->m_command->Step())
            resultList.push_back(GetRow());

        this->m_command->Reset();
        return resultList;
    }

    template<typename ColumnList, typename CustomRow>
    CustomRow GetCustomSingleRow()
    {
        Prepare(JoinUtil<ColumnList>::GetColumnNames().c_str());
        Bind();
        this->m_command->Step();

        CustomRow result = GetCustomRow<ColumnList, CustomRow>();

        this->m_command->Reset();
        return result;
    }

    template<typename ColumnList, typename CustomRow>
    std::list<CustomRow> GetCustomRowList()
    {
        Prepare(JoinUtil<ColumnList>::GetColumnNames().c_str());
        Bind();

        std::list<CustomRow> resultList;

        while (this->m_command->Step())
            resultList.push_back(GetCustomRow<ColumnList, CustomRow>());

        this->m_command->Reset();
        return resultList;
    }
};

template<typename TableDefinition>
class __attribute__ ((visibility("hidden"))) Update : public QueryWithWhereClause<TableDefinition> {
public:
    typedef typename TableDefinition::Row Row;

protected:
    boost::optional<std::string> m_orClause;
    Row m_row;

    class PrepareVisitor {
    public:
        std::string m_setExpressions;

        template<typename ColumnType>
        void Visit(const char* name, const ColumnType&, bool isSet)
        {
            if ( isSet )
            {
                if ( !m_setExpressions.empty() )
                {
                    m_setExpressions += ", ";
                }
                m_setExpressions += name;
                m_setExpressions += " = ";
                m_setExpressions += "?";
            }
        }
    };

    void Prepare()
    {
        if ( !this->m_command )
        {
            this->m_commandString = "UPDATE ";
            if ( !!m_orClause )
            {
                this->m_commandString += " OR " + *m_orClause + " ";
            }
            this->m_commandString += TableDefinition::GetName();
            this->m_commandString += " SET ";

            // got through row columns and values
            PrepareVisitor visitor;
            m_row.VisitColumns(visitor);

            if(visitor.m_setExpressions.empty())
            {
                ThrowMsg(Exception::EmptyUpdateStatement, "No SET expressions in update statement");
            }

            this->m_commandString += visitor.m_setExpressions;

            // where
            QueryWithWhereClause<TableDefinition>::Prepare();

            this->m_command = TableDefinition::AllocTableDataCommand(
                    this->m_commandString.c_str(),
                    Query<TableDefinition>::m_interface);
            VcoreLogD("Prepared SQL command %s", this->m_commandString.c_str());
        }
    }

    void Bind()
    {
        BindVisitor visitor(this->m_command);
        m_row.VisitColumns(visitor);

        this->m_bindArgumentIndex = visitor.m_bindArgumentIndex;
        QueryWithWhereClause<TableDefinition>::Bind();
    }


public:
    explicit Update(IOrmInterface *interface = NULL,
                    const boost::optional<std::string>& orClause = boost::optional<std::string>()) :
        QueryWithWhereClause<TableDefinition>(interface),
        m_orClause(orClause)
    {
    }

    void Values(const Row& row)
    {
        if ( this->m_command )
        {
            if ( !row.IsSignatureMatching(m_row) )
            {
                ThrowMsg(Exception::SelectReuseWithDifferentQuerySignature,
                    "Current ORM implementation doesn't allow to reuse Update instance "
                    "with different query signature.");
            }
        }
        m_row = row;
    }

    void Execute()
    {
        Prepare();
        Bind();
        this->m_command->Step();
        this->m_command->Reset();
    }
};

} //namespace ORM
} //namespace DB
} //namespace VcoreDPL

#endif // DPL_ORM_H
