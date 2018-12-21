#include "ecs_db.h"
#include <iostream>
#include <stdio.h>

namespace ecsm {

static std::string int2Str(int i)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%d", i);
    return std::string(buf);
}

static std::string wapperStr(std::string& str)
{
    return "'" + str + "'";
}

std::string EcsDB::create_Ecs_Tbl_SQL()
{
    char sql_bf[4096] = {'\0'};
    snprintf(sql_bf, sizeof(sql_bf), "%s \"%s\" (%s)", 
            "CREATE TABLE", kEcsTable.c_str(),
            "`id`    INTEGER UNIQUE,"
            "`house_id`  INTEGER NOT NULL,"
            "`site_name` TEXT,"
            "`ecs_id` INTEGER NOT NULL,"
            "`is_public`    INTEGER,"
            "`wan_ip`    TEXT,"
            "`wan_port`  TEXT,"
            "`user_wan`  TEXT,"
            "`passwd_wan`    TEXT,"
            "`lan_ip`    TEXT,"
            "`lan_port`  INTEGER,"
            "`user_lan`  TEXT,"
            "`passwd_lan`   TEXT,"
            "`permission_start`  TEXT,"
            "`permission_end`    TEXT,"
            "`license_info`  TEXT,"
            "PRIMARY KEY(id)"
            );
    return std::string(sql_bf);
}

std::string EcsDB::create_BasicConfig_Tbl_SQL()
{
    char sql_bf[4096] = {'\0'};
    snprintf(sql_bf, sizeof(sql_bf), "%s \"%s\" (%s)", 
            "CREATE TABLE", kEcsBasicConfigTable.c_str(),
            "`id`    INTEGER UNIQUE,"
            "`house_id`  INTEGER,"
            "`ecs_id` INTEGER,"
            "`ecs_id_str` TEXT,"
            "`idc_id`    INTEGER,"
            "`install_dir`   TEXT,"
            "`huge_page` INTEGER,"
            "`rst_interface` TEXT,"
            "`rst_mode`  TEXT,"
            "`rst_dst_mac`   TEXT,"
            "`upload_Type`   TEXT,"
            "`dpdk_eth_grep` TEXT,"
            "PRIMARY KEY(id)"
            );
    return std::string(sql_bf);
}

std::string EcsDB::create_MachineInfo_Tbl_SQL()
{
    char sql_bf[4096] = {'\0'};
    snprintf(sql_bf, sizeof(sql_bf), "%s \"%s\" (%s)", 
            "CREATE TABLE", kEcsMachineInfoTable.c_str(),
            "`id`    INTEGER UNIQUE,"
            "`house_id`  INTEGER,"
            "`ecs_id` INTEGER,"
            "`hostname`  TEXT,"
            "`board_serial`  TEXT,"
            "`cpu_number`    INTEGER,"
            "`cpu_modles`    TEXT,"
            "`eth_pci_addr`  TEXT,"
            "PRIMARY KEY(id)"
            );
    return std::string(sql_bf);
}

int EcsDB::checkAndCreateTables(SQLite::Database& db) 
{
    if (!db.tableExists(kEcsTable)) {
        try {
            db.exec(create_Ecs_Tbl_SQL());
        } catch (std::exception& e) {
            std::cout << "SQLite exception: " << e.what() << std::endl;
            return -1;
        }
    }    

    if (!db.tableExists(kEcsBasicConfigTable)) {
        try {
            db.exec(create_BasicConfig_Tbl_SQL());
        } catch (std::exception& e) {
            std::cout << "SQLite exception: " << e.what() << std::endl;
            return -1;
        }
    }    

    if (!db.tableExists(kEcsMachineInfoTable)) {
        try {
            db.exec(create_MachineInfo_Tbl_SQL());
        } catch (std::exception& e) {
            std::cout << "SQLite exception: " << e.what() << std::endl;
            return -1;
        }
    }
    return 0;
}

int EcsDB::dbInsertUpdate(int houseID, int euID, SQLite::Database* db_p, std::string& tbl_name, std::vector<std::string>& key_v)
{
    int if_update = 0;
    std::string keys;
    std::string values;
    std::string sql;
    char clause[256];

    snprintf(clause, sizeof clause, "WHERE house_id =%d and ecs_id =%d", houseID, euID);
    if (db_p->getRowCount(tbl_name.c_str(), clause) > 0) {
        if_update = 1;
    }

    if (if_update) {
        sql = "UPDATE " + tbl_name + " " + "SET ";
        for (std::vector<std::string>::iterator it = key_v.begin(); it < key_v.end(); it += 2) {
            sql += *it + "=" + *(it + 1) + ",";
        }
        sql.erase(sql.find_last_not_of(", \n\r\t") + 1);
        sql += " ";
        sql += clause;

    } else {
        keys.append("(");
        values.append("VALUES (");
        for (std::vector<std::string>::iterator it = key_v.begin(); it < key_v.end(); it += 2) {
            keys += *it + ",";
            values += *(it + 1) + ",";
        }
        keys.erase(keys.find_last_not_of(", \n\r\t") + 1);
        values.erase(values.find_last_not_of(", \n\r\t") + 1);
        keys.append(")");
        values.append(")");
        sql = "INSERT INTO " + tbl_name + " " + keys + " " + values;
    } 
    //std::cout << sql << std::endl;
    SQLite::Transaction transaction(*db_p);
    db_p->exec(sql);
    transaction.commit();
    return 0;
}   

EcsTblRow::EcsTblRow(SQLite::Database* db)
    : m_db_p(db), m_name(kEcsTable)
{
    id = -1;
    house_id = -1;
    site_name = "";
    ecs_id = -1;
    is_public = -1;
    wan_ip = "";
    wan_port = -1;
    user_wan = "";
    passwd_wan = "";
    lan_ip = "";
    lan_port = -1;
    user_lan = "";
    passwd_lan = "";
    permission_start = "";
    permission_end = "";
    license_info = "";
}

void EcsTblRow::printRow()
{
    std::cout << "id=" << id << std::endl;
    std::cout << "house_id=" << house_id << std::endl;
    std::cout << "site_name=" << site_name << std::endl;
    std::cout << "ecs_id=" << ecs_id << std::endl;

    std::cout << "wan_ip=" << wan_ip << std::endl;
    std::cout << "wan_port=" << wan_port << std::endl;
    std::cout << "user_wan=" << user_wan << std::endl;
    std::cout << "passwd_wan=" << passwd_wan << std::endl;
    
    std::cout << "lan_ip=" << lan_ip << std::endl;
    std::cout << "lan_port=" << lan_port << std::endl;    
    std::cout << "user_lan=" << user_lan << std::endl;
    std::cout << "passwd_lan=" << passwd_lan << std::endl;

    std::cout << "permission_start=" << permission_start << std::endl;
    std::cout << "permission_end=" << permission_end << std::endl;    
    std::cout << "license_info=" << license_info << std::endl;
    std::cout << std::endl;
}

void EcsTblRow::getRow(SQLite::Statement& query)
{
    id = query.getColumn("id").getInt();
    house_id = query.getColumn("house_id").getInt();
    site_name = query.getColumn("site_name").getString();
    ecs_id = query.getColumn("ecs_id").getInt();
    is_public = query.getColumn("is_public").getInt();

    wan_ip = query.getColumn("wan_ip").getString();
    wan_port = query.getColumn("wan_port").getInt();
    user_wan = query.getColumn("user_wan").getString();
    passwd_wan = query.getColumn("passwd_wan").getString();

    lan_ip = query.getColumn("lan_ip").getString();
    lan_port = query.getColumn("lan_port").getInt();
    user_lan = query.getColumn("user_lan").getString();
    passwd_lan = query.getColumn("passwd_lan").getString();

    permission_start = query.getColumn("permission_start").getString();
    permission_end = query.getColumn("permission_end").getString();
    license_info = query.getColumn("license_info").getString();
}

int EcsTblRow::getRow(int houseID, int euID)
{
    char sql[156];
    char clause[128];
    snprintf(clause, sizeof clause, "WHERE house_id =%d AND ecs_id =%d", houseID, euID);
    snprintf(sql, sizeof(sql), "SELECT * from %s %s", m_name.c_str(), clause);

    if (m_db_p->getRowCount(m_name.c_str(), clause) == 0) {
        return 0;
    }

    SQLite::Statement query(*m_db_p, sql);
    query.executeStep();
    getRow(query);
    return 1;
}

void EcsTblRow::insertRow(int houseID, int euID)
{
    std::vector<std::string> key_v;
    if (id != -1) {
        key_v.push_back("id"); key_v.push_back(int2Str(id));
    }
    if (house_id != -1) {
        key_v.push_back("house_id"); key_v.push_back(int2Str(house_id));
    }
    if (ecs_id != -1) {
        key_v.push_back("ecs_id"); key_v.push_back(int2Str(ecs_id));
    }
    if (is_public != -1) {
        key_v.push_back("is_public"); key_v.push_back(int2Str(is_public));
    }
    if (wan_port != -1) {
        key_v.push_back("wan_port"); key_v.push_back(int2Str(wan_port));
    }
    if (lan_port != -1) {
        key_v.push_back("lan_port"); key_v.push_back(int2Str(lan_port));
    }
    if (site_name.size() != 0) {
        key_v.push_back("site_name"); key_v.push_back(wapperStr(site_name));
    }
    if (wan_ip.size() != 0) {
        key_v.push_back("wan_ip"); key_v.push_back(wapperStr(wan_ip));
    }
    if (user_wan.size() != 0) {
        key_v.push_back("user_wan"); key_v.push_back(wapperStr(user_wan));
    }
    if (passwd_wan.size() != 0) {
        key_v.push_back("passwd_wan"); key_v.push_back(wapperStr(passwd_wan));
    }
    if (lan_ip.size() != 0) {
        key_v.push_back("lan_ip"); key_v.push_back(wapperStr(lan_ip));
    }
    if (user_lan.size() != 0) {
        key_v.push_back("user_lan"); key_v.push_back(wapperStr(user_lan));
    }
    if (passwd_lan.size() != 0) {
        key_v.push_back("passwd_lan"); key_v.push_back(wapperStr(passwd_lan));
    }
    EcsDB::dbInsertUpdate(houseID, euID, m_db_p, m_name, key_v);
}

int EcsTblRow::selectID(int houseid, int euid)
{
    std::string thisSQL("SELECT id from ");
    char clause[256];
    snprintf(clause, sizeof clause, "WHERE ecs_id=%d and house_id=%d", euid, houseid);
    thisSQL += m_name + " " + clause;
    if (0 == m_db_p->getRowCount(m_name.c_str(), clause)) {
        return -1;
    }
    return m_db_p->execAndGet(thisSQL);
}

void EcsTblRow::deleteRow(int houseid, int euid)
{
    std::string thisSQL("DELETE from ");
    char clause[256];
    snprintf(clause, sizeof clause, "WHERE ecs_id=%d and house_id=%d", euid, houseid);
    thisSQL += m_name + " " + clause;

    SQLite::Transaction transaction(*m_db_p);
    m_db_p->exec(thisSQL);
    transaction.commit();
}

EcsMachineInfoTblRow::EcsMachineInfoTblRow(SQLite::Database* db) 
    : m_db_p(db), m_name(kEcsMachineInfoTable)
{
    id = -1;
    house_id = -1;
    ecs_id = -1;
    hostname = "";
    board_serial = "";
    cpu_number = -1;
    cpu_modles = "";
    eth_pci_addr = "";
}

void EcsMachineInfoTblRow::getRow(SQLite::Statement& query)
{
    id = query.getColumn("id").getInt();
    house_id = query.getColumn("house_id").getInt();
    ecs_id = query.getColumn("ecs_id").getInt();
    hostname = query.getColumn("hostname").getString();
    cpu_number = query.getColumn("cpu_number").getInt();
    board_serial = query.getColumn("board_serial").getString();
    cpu_modles = query.getColumn("cpu_modles").getString();
    eth_pci_addr = query.getColumn("eth_pci_addr").getString();
}

int EcsMachineInfoTblRow::getRow(int houseID, int euID)
{
    char sql[156];
    char clause[128];
    snprintf(clause, sizeof clause, "WHERE house_id =%d AND ecs_id =%d", houseID, euID);
    snprintf(sql, sizeof(sql), "SELECT * from %s %s", m_name.c_str(), clause);

    if (m_db_p->getRowCount(m_name.c_str(), clause) == 0) {
        return 0;
    }

    SQLite::Statement query(*m_db_p, sql);
    query.executeStep();
    getRow(query);
}

void EcsMachineInfoTblRow::printRow()
{

}

void EcsMachineInfoTblRow::insertRow(int houseID, int euID)
{
    std::string insert_sql;
    std::vector<std::string> key_v;
    if (id != -1) {
        key_v.push_back("id"); key_v.push_back(int2Str(id));
    }
    if (house_id != -1) {
        key_v.push_back("house_id"); key_v.push_back(int2Str(house_id));
    }
    if (ecs_id != -1) {
        key_v.push_back("ecs_id"); key_v.push_back(int2Str(ecs_id));
    }
    if (cpu_number != -1) {
        key_v.push_back("cpu_number"); key_v.push_back(int2Str(cpu_number));
    }
    if (hostname.size() != 0) {
        key_v.push_back("hostname"); key_v.push_back(wapperStr(hostname));
    }
    if (board_serial.size() != 0) {
        key_v.push_back("board_serial"); key_v.push_back(wapperStr(board_serial));
    }
    if (cpu_modles.size() != 0) {
        key_v.push_back("cpu_modles"); key_v.push_back(wapperStr(cpu_modles));
    }
    if (eth_pci_addr.size() != 0) {
        key_v.push_back("eth_pci_addr"); key_v.push_back(wapperStr(eth_pci_addr));
    }
    EcsDB::dbInsertUpdate(houseID, euID, m_db_p, m_name, key_v);
}

EcsBasicConfigTblRow::EcsBasicConfigTblRow(SQLite::Database* db) 
    : m_db_p(db), m_name(kEcsBasicConfigTable)
{
    id = -1;
    house_id = -1;
    ecs_id = -1;
    ecs_id_str = "";
    idc_id = "";
    install_dir = "";
    huge_page = -1;
    rst_interface = "";
    upload_Type = "";
    rst_mode = "";
    rst_dst_mac = "";
    dpdk_eth_grep = "";
}
//UPDATE COMPANY SET ADDRESS = 'Texas' WHERE ID = 6;
//INSERT INTO COMPANY (ID,NAME,AGE,ADDRESS,SALARY) VALUES (1, 'Paul', 32, 'California', 20000.00 );
void EcsBasicConfigTblRow::insertRow(int houseID, int euID)
{
    std::vector<std::string> key_v;
    if (id != -1) {
        key_v.push_back("id"); key_v.push_back(int2Str(id));
    }
    if (house_id != -1) {
        key_v.push_back("house_id"); key_v.push_back(int2Str(house_id));
    }
    if (ecs_id != -1) {
        key_v.push_back("ecs_id"); key_v.push_back(int2Str(ecs_id));
    }
    if (huge_page != -1) {
        key_v.push_back("huge_page"); key_v.push_back(int2Str(huge_page));
    }
    if (ecs_id_str.size() != 0) {
        key_v.push_back("ecs_id_str"); key_v.push_back(wapperStr(ecs_id_str));
    }
    if (idc_id.size() != 0) {
        key_v.push_back("idc_id"); key_v.push_back(wapperStr(idc_id));
    }
    if (install_dir.size() != 0) {
        key_v.push_back("install_dir"); key_v.push_back(wapperStr(install_dir));
    }
    if (rst_interface.size() != 0) {
        key_v.push_back("rst_interface"); key_v.push_back(wapperStr(rst_interface));
    }    
    if (upload_Type.size() != 0) {
        key_v.push_back("upload_Type"); key_v.push_back(wapperStr(upload_Type));
    }
    if (rst_mode.size() != 0) {
        key_v.push_back("rst_mode"); key_v.push_back(wapperStr(rst_mode));
    }
    if (rst_dst_mac.size() != 0) {
        key_v.push_back("rst_dst_mac"); key_v.push_back(wapperStr(rst_dst_mac));
    }
    if (dpdk_eth_grep.size() != 0) {
        key_v.push_back("dpdk_eth_grep"); key_v.push_back(wapperStr(dpdk_eth_grep));
    }
    EcsDB::dbInsertUpdate(houseID, euID, m_db_p, m_name, key_v);
}

void EcsBasicConfigTblRow::getRow(SQLite::Statement& query)
{
    id = query.getColumn("id").getInt();
    house_id = query.getColumn("house_id").getInt();
    ecs_id = query.getColumn("ecs_id").getInt();
    ecs_id_str = query.getColumn("ecs_id_str").getString();
    idc_id = query.getColumn("idc_id").getString();
    install_dir = query.getColumn("install_dir").getString();
    huge_page = query.getColumn("huge_page").getInt();
    rst_interface = query.getColumn("rst_interface").getString();
    upload_Type = query.getColumn("upload_Type").getString();
    rst_mode = query.getColumn("rst_mode").getString();
    rst_dst_mac = query.getColumn("rst_dst_mac").getString();
    dpdk_eth_grep = query.getColumn("dpdk_eth_grep").getString();
}

int EcsBasicConfigTblRow::getRow(int houseID, int euID)
{
    char sql[156];
    char clause[128];
    snprintf(clause, sizeof clause, "WHERE house_id =%d AND ecs_id =%d", houseID, euID);
    snprintf(sql, sizeof(sql), "SELECT * from %s %s", m_name.c_str(), clause);

    if (m_db_p->getRowCount(m_name.c_str(), clause) == 0) {
        return 0;
    }

    SQLite::Statement query(*m_db_p, sql);
    query.executeStep();
    getRow(query);
}

void EcsBasicConfigTblRow::printRow()
{

}


} //end namespace
