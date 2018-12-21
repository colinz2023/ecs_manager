#ifndef _ECS_DB_H
#define _ECS_DB_H

#include <string>
#include <stdint.h>
#include <vector>
#include "SQLiteCpp.h"

namespace ecsm {

const std::string kDefaultEcsDb = "ecs.db";
const std::string kEcsTable = "t_eu";
const std::string kEcsBasicConfigTable = "t_basic_config";
const std::string kEcsMachineInfoTable = "t_machine_info";

class DBTable
{
public:
    virtual void getRow(SQLite::Statement& query) = 0;
    virtual void printRow() = 0;
    virtual void insertRow(int houseID, int euID) = 0;
    //virtual void updateRow() = 0;
};

class EcsTblRow : public DBTable
{
public:
    int id;
    int house_id;
    std::string site_name;
    int ecs_id;
    int is_public;
    std::string wan_ip;
    int wan_port;
    std::string user_wan;
    std::string passwd_wan;
    std::string lan_ip;
    int lan_port;
    std::string user_lan;
    std::string passwd_lan;
    std::string permission_start;
    std::string permission_end;
    std::string license_info;
public:
    EcsTblRow(SQLite::Database* db);
    virtual void getRow(SQLite::Statement& query);
    virtual void printRow();
    virtual void insertRow(int houseID, int euID);
    int getRow(int houseID, int euID);
    void deleteRow(int houseid, int euid);
    int selectID(int houseid, int euid);
private:
    SQLite::Database* m_db_p;
    std::string m_name;
};

class EcsMachineInfoTblRow : public DBTable
{
public:
    int id;
    int house_id;
    int ecs_id;
    std::string hostname;
    std::string board_serial;
    int cpu_number;
    std::string cpu_modles;
    std::string eth_pci_addr;
public:
    EcsMachineInfoTblRow(SQLite::Database* db);
    virtual void getRow(SQLite::Statement& query);
    virtual void printRow();
    virtual void insertRow(int houseID, int euID);
    int getRow(int houseID, int euID);
private:
    SQLite::Database* m_db_p;
    std::string m_name;
};

class EcsBasicConfigTblRow : public DBTable
{
public:
    int id;
    int house_id;
    int ecs_id;
    std::string ecs_id_str;
    std::string idc_id;
    std::string install_dir;
    int huge_page;
    std::string rst_interface;
    std::string rst_mode;
    std::string rst_dst_mac;
    std::string upload_Type;
    std::string customer_name;
    std::string dpdk_eth_grep;
public:
    EcsBasicConfigTblRow(SQLite::Database* db);
    virtual void getRow(SQLite::Statement& query);
    virtual void printRow();
    virtual void insertRow(int houseID, int euID);
    int getRow(int houseID, int euID);
private:
    SQLite::Database* m_db_p;
    std::string m_name;
};

class EcsDB
{
public:
    static std::string create_Ecs_Tbl_SQL();
    static std::string create_BasicConfig_Tbl_SQL();
    static std::string create_MachineInfo_Tbl_SQL();
    static int checkAndCreateTables(SQLite::Database& db);
    static int dbInsertUpdate(int houseID, int euID, SQLite::Database* db_p, 
                                std::string& tbl_name, std::vector<std::string>& key_v);
};



} //end of namespace

#endif
