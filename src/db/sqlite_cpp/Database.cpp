/**
 * @file    Database.cpp
 * @ingroup SQLiteCpp
 * @brief   Management of a SQLite Database Connection.
 *
 * Copyright (c) 2012-2016 Sebastien Rombauts (sebastien.rombauts@gmail.com)
 *
 * Distributed under the MIT License (MIT) (See accompanying file LICENSE.txt
 * or copy at http://opensource.org/licenses/MIT)
 */
#include "Database.h"
#include "Statement.h"
#include "Assertion.h"
#include "Exception.h"

#include <sqlite3.h>
#include <stdio.h>

#ifndef SQLITE_DETERMINISTIC
#define SQLITE_DETERMINISTIC 0x800
#endif // SQLITE_DETERMINISTIC


namespace SQLite
{

const int   OPEN_READONLY   = SQLITE_OPEN_READONLY;
const int   OPEN_READWRITE  = SQLITE_OPEN_READWRITE;
const int   OPEN_CREATE     = SQLITE_OPEN_CREATE;
const int   OPEN_URI        = SQLITE_OPEN_URI;
const int   OPEN_MEMORY     = SQLITE_OPEN_MEMORY;

const int   OK              = SQLITE_OK;

const char* VERSION         = SQLITE_VERSION;
const int   VERSION_NUMBER  = SQLITE_VERSION_NUMBER;

// Return SQLite version string using runtime call to the compiled library
const char* getLibVersion() noexcept // nothrow
{
    return sqlite3_libversion();
}

// Return SQLite version number using runtime call to the compiled library
const int getLibVersionNumber() noexcept // nothrow
{
    return sqlite3_libversion_number();
}


// Open the provided database UTF-8 filename with SQLite::OPEN_xxx provided flags.
Database::Database(const char* apFilename,
                   const int   aFlags         /* = SQLite::OPEN_READONLY*/,
                   const int   aBusyTimeoutMs /* = 0 */,
                   const char* apVfs          /* = NULL*/) :
    mpSQLite(NULL),
    mFilename(apFilename)
{
    const int ret = sqlite3_open_v2(apFilename, &mpSQLite, aFlags, apVfs);
    if (SQLITE_OK != ret)
    {
        const SQLite::Exception exception(mpSQLite, ret); // must create before closing
        sqlite3_close(mpSQLite); // close is required even in case of error on opening
        throw exception;
    }

    if (aBusyTimeoutMs > 0)
    {
        setBusyTimeout(aBusyTimeoutMs);
    }
}

// Open the provided database UTF-8 filename with SQLite::OPEN_xxx provided flags.
Database::Database(const std::string& aFilename,
                   const int          aFlags         /* = SQLite::OPEN_READONLY*/,
                   const int          aBusyTimeoutMs /* = 0 */,
                   const std::string& aVfs           /* = "" */) :
    mpSQLite(NULL),
    mFilename(aFilename)
{
    const int ret = sqlite3_open_v2(aFilename.c_str(), &mpSQLite, aFlags, aVfs.empty() ? NULL : aVfs.c_str());
    if (SQLITE_OK != ret)
    {
        const SQLite::Exception exception(mpSQLite, ret); // must create before closing
        sqlite3_close(mpSQLite); // close is required even in case of error on opening
        throw exception;
    }

    if (aBusyTimeoutMs > 0)
    {
        setBusyTimeout(aBusyTimeoutMs);
    }
}

// Close the SQLite database connection.
Database::~Database() noexcept // nothrow
{
    const int ret = sqlite3_close(mpSQLite);

    // Avoid unreferenced variable warning when build in release mode
    (void) ret;

    // Only case of error is SQLITE_BUSY: "database is locked" (some statements are not finalized)
    // Never throw an exception in a destructor :
    SQLITECPP_ASSERT(SQLITE_OK == ret, "database is locked");  // See SQLITECPP_ENABLE_ASSERT_HANDLER
}

/**
 * @brief Set a busy handler that sleeps for a specified amount of time when a table is locked.
 *
 *  This is useful in multithreaded program to handle case where a table is locked for writting by a thread.
 * Any other thread cannot access the table and will receive a SQLITE_BUSY error:
 * setting a timeout will wait and retry up to the time specified before returning this SQLITE_BUSY error.
 *  Reading the value of timeout for current connection can be done with SQL query "PRAGMA busy_timeout;".
 *  Default busy timeout is 0ms.
 *
 * @param[in] aBusyTimeoutMs    Amount of milliseconds to wait before returning SQLITE_BUSY
 *
 * @throw SQLite::Exception in case of error
 */
void Database::setBusyTimeout(const int aBusyTimeoutMs) noexcept // nothrow
{
    const int ret = sqlite3_busy_timeout(mpSQLite, aBusyTimeoutMs);
    check(ret);
}

// Shortcut to execute one or multiple SQL statements without results (UPDATE, INSERT, ALTER, COMMIT, CREATE...).
int Database::exec(const char* apQueries)
{
    const int ret = sqlite3_exec(mpSQLite, apQueries, NULL, NULL, NULL);
    check(ret);

    // Return the number of rows modified by those SQL statements (INSERT, UPDATE or DELETE only)
    return sqlite3_changes(mpSQLite);
}

// Shortcut to execute a one step query and fetch the first column of the result.
// WARNING: Be very careful with this dangerous method: you have to
// make a COPY OF THE result, else it will be destroy before the next line
// (when the underlying temporary Statement and Column objects are destroyed)
// this is an issue only for pointer type result (ie. char* and blob)
// (use the Column copy-constructor)
Column Database::execAndGet(const char* apQuery)
{
    Statement query(*this, apQuery);
    (void)query.executeStep(); // Can return false if no result, which will throw next line in getColumn()
    return query.getColumn(0);
}


int Database::getRowCount(const char* table_name)
{
    char buf[128];
    snprintf(buf, sizeof buf, "SELECT count(*) FROM %s", table_name);
    Statement query(*this, buf);
    (void)query.executeStep();
    return query.getColumn(0).getInt();
}

int Database::getRowCount(const char* table_name, const char* where_clause)
{
    char buf[128];
    snprintf(buf, sizeof buf, "SELECT count(*) FROM %s %s", table_name, where_clause);
    Statement query(*this, buf);
    (void)query.executeStep();
    return query.getColumn(0).getInt();
}

// Shortcut to test if a table exists.
bool Database::tableExists(const char* apTableName)
{
    Statement query(*this, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?");
    query.bind(1, apTableName);
    (void)query.executeStep(); // Cannot return false, as the above query always return a result
    return (1 == query.getColumn(0).getInt());
}

// Get the rowid of the most recent successful INSERT into the database from the current connection.
long long Database::getLastInsertRowid() const noexcept // nothrow
{
    return sqlite3_last_insert_rowid(mpSQLite);
}

// Get total number of rows modified by all INSERT, UPDATE or DELETE statement since connection.
int Database::getTotalChanges() const noexcept // nothrow
{
    return sqlite3_total_changes(mpSQLite);
}

// Return the numeric result code for the most recent failed API call (if any).
int Database::getErrorCode() const noexcept // nothrow
{
    return sqlite3_errcode(mpSQLite);
}

// Return the extended numeric result code for the most recent failed API call (if any).
int Database::getExtendedErrorCode() const noexcept // nothrow
{
    return sqlite3_extended_errcode(mpSQLite);
}

// Return UTF-8 encoded English language explanation of the most recent failed API call (if any).
const char* Database::getErrorMsg() const noexcept // nothrow
{
    return sqlite3_errmsg(mpSQLite);
}

// Attach a custom function to your sqlite database. Assumes UTF8 text representation.
// Parameter details can be found here: http://www.sqlite.org/c3ref/create_function.html
void Database::createFunction(const char*   apFuncName,
                              int           aNbArg,
                              bool          abDeterministic,
                              void*         apApp,
                              void        (*apFunc)(sqlite3_context *, int, sqlite3_value **),
                              void        (*apStep)(sqlite3_context *, int, sqlite3_value **),
                              void        (*apFinal)(sqlite3_context *),   // NOLINT(readability/casting)
                              void        (*apDestroy)(void *))
{
    int TextRep = SQLITE_UTF8;
    // optimization if deterministic function (e.g. of nondeterministic function random())
    if (abDeterministic) {
        TextRep = TextRep|SQLITE_DETERMINISTIC;
    }
    const int ret = sqlite3_create_function_v2(mpSQLite, apFuncName, aNbArg, TextRep,
                                               apApp, apFunc, apStep, apFinal, apDestroy);
    check(ret);
}

// Load an extension into the sqlite database. Only affects the current connection.
// Parameter details can be found here: http://www.sqlite.org/c3ref/load_extension.html
void Database::loadExtension(const char* apExtensionName, const char *apEntryPointName)
{
#ifdef SQLITE_OMIT_LOAD_EXTENSION
    throw std::runtime_error("sqlite extensions are disabled");
#else
#ifdef SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION // Since SQLite 3.13 (2016-05-18):
    // Security warning:
    // It is recommended that the SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION method be used to enable only this interface.
    // The use of the sqlite3_enable_load_extension() interface should be avoided to keep the SQL load_extension()
    // disabled and prevent SQL injections from giving attackers access to extension loading capabilities.
    int ret = sqlite3_db_config(mpSQLite, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 1, NULL);
#else
    int ret = sqlite3_enable_load_extension(mpSQLite, 1);
#endif
    check(ret);

    ret = sqlite3_load_extension(mpSQLite, apExtensionName, apEntryPointName, 0);
    check(ret);
#endif
}

}  // namespace SQLite
