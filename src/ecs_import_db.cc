//
//  Created by zhangm on 2017/3
//
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include "ecs_db.h"
#include "utils.h"

int importFile(const char* file, SQLite::Database& db)
{
    std::ifstream inf(file, std::ifstream::binary);
    char secs[256][128];
    char line_buff[1024];
    std::string en_str;
    int x = 0;
    while (! inf.getline(line_buff, sizeof(line_buff)).eof()) {
        char* p = NULL;
        int j = 0;
        memset(secs, 0, sizeof(secs));
        p = strtok(line_buff, ",|");
        while (NULL != p) {
            char* pp = ecsm::StringUtils::cstringTrim(p, strlen(p));
            snprintf(secs[j], 128, "%s", pp);
            //std::cout << "secs:" << secs[j] << std::endl;
            p = strtok(NULL, ",|");
            j++;
        }
        if (j < 10) continue;
        //std::cout << "secs[10]:" << secs[10] << std::endl;
        int ecs_num = atoi(secs[10]);
        int ecs_id_start = atoi(secs[11]);
        int public_ecs_id = atoi(secs[12]);
        int a, b, c, d;
        sscanf(secs[6], "%d.%d.%d.%d", &a, &b, &c, &d);
        for (int i = 0; i < ecs_num; i++) {
            char lan_ip[128];
            snprintf(lan_ip, sizeof(lan_ip), "%d.%d.%d.%d", a, b, c, d + i);
            ecsm::EcsTblRow ecs_tbl_row(&db);
            ecs_tbl_row.house_id = atoi(secs[0]);
            ecs_tbl_row.site_name = secs[1];
            ecs_tbl_row.ecs_id = (i + ecs_id_start);
            ecs_tbl_row.is_public = (public_ecs_id == i + ecs_id_start ? 1 : 0);
            ecs_tbl_row.wan_ip = secs[2];
            ecs_tbl_row.wan_port = atoi(secs[3]);
            ecs_tbl_row.user_wan = secs[4];
            ecsm::encrypto(secs[5], 64, &en_str);
            ecs_tbl_row.passwd_wan = en_str;
            ecs_tbl_row.lan_ip = lan_ip;
            ecs_tbl_row.lan_port = atoi(secs[7]);
            ecs_tbl_row.user_lan = secs[8];
            ecsm::encrypto(secs[9], 64, &en_str);
            ecs_tbl_row.passwd_lan = en_str;
            ecs_tbl_row.insertRow(ecs_tbl_row.house_id, ecs_tbl_row.ecs_id);

            ecsm::EcsBasicConfigTblRow ebctr(&db);
            char ecs_id_str[16];
            snprintf(ecs_id_str, sizeof ecs_id_str, "test%03d", ecs_tbl_row.ecs_id);
            ebctr.ecs_id = ecs_tbl_row.ecs_id;
            ebctr.house_id = ecs_tbl_row.house_id;
            ebctr.idc_id = "123456789";
            ebctr.ecs_id_str = ecs_id_str;
            ebctr.install_dir = "/opt/test";
            ebctr.huge_page = 1024;
            ebctr.rst_interface = "eno2";
            ebctr.rst_mode = "c|s";
            ebctr.upload_Type = "CU";
            ebctr.dpdk_eth_grep = "10G";
            ebctr.rst_dst_mac = secs[13][0] == 0 ? " " : secs[13];
            ebctr.insertRow(ebctr.house_id, ebctr.ecs_id);
        }
    }
    inf.close();
    return 0;
}

int importFileNoSkip(const char* file, SQLite::Database& db)
{
    std::ifstream inf(file, std::ifstream::binary);
    char secs[256][128];
    char line_buff[1024];
    std::string en_str;
    int x = 0;
    while (! inf.getline(line_buff, sizeof(line_buff)).eof()) {
        char* p = NULL;
        int j = 0;
        memset(secs, 0, sizeof(secs));
        p = strtok(line_buff, ",|");
        while (NULL != p) {
            char* pp = ecsm::StringUtils::cstringTrim(p, strlen(p));
            snprintf(secs[j], 128, "%s", pp);
            //std::cout << "secs:" << secs[j] << std::endl;
            p = strtok(NULL, ",|");
            j++;
        }
        if (j < 10) continue;
        //std::cout << "secs[10]:" << secs[10] << std::endl;
        int ecs_num = atoi(secs[10]);
        int ecs_id_start = atoi(secs[11]);
        int public_ecs_id = atoi(secs[12]);
        int a, b, c, d;
        int aa, bb, cc, dd;
        sscanf(secs[6], "%d.%d.%d.%d", &a, &b, &c, &d);
        sscanf(secs[2], "%d.%d.%d.%d", &aa, &bb, &cc, &dd);
        for (int i = 0; i < ecs_num; i++) {
            char lan_ip[128];
            char wan_ip[128];
            snprintf(lan_ip, sizeof(lan_ip), "%d.%d.%d.%d", a, b, c, d + i);
            snprintf(wan_ip, sizeof(wan_ip), "%d.%d.%d.%d", aa, bb, cc, dd + i);
            ecsm::EcsTblRow ecs_tbl_row(&db);
            ecs_tbl_row.house_id = atoi(secs[0]);
            ecs_tbl_row.site_name = secs[1];
            ecs_tbl_row.ecs_id = (i + ecs_id_start);
            ecs_tbl_row.is_public = 1;
            ecs_tbl_row.wan_ip = wan_ip;
            ecs_tbl_row.wan_port = atoi(secs[3]);
            ecs_tbl_row.user_wan = secs[4];
            ecsm::encrypto(secs[5], 64, &en_str);
            ecs_tbl_row.passwd_wan = en_str;
            ecs_tbl_row.lan_ip = lan_ip;
            ecs_tbl_row.lan_port = atoi(secs[7]);
            ecs_tbl_row.user_lan = secs[8];
            ecsm::encrypto(secs[9], 64, &en_str);
            ecs_tbl_row.passwd_lan = en_str;
            ecs_tbl_row.insertRow(ecs_tbl_row.house_id, ecs_tbl_row.ecs_id);

            ecsm::EcsBasicConfigTblRow ebctr(&db);
            char ecs_id_str[16];
            snprintf(ecs_id_str, sizeof ecs_id_str, "test%03d", ecs_tbl_row.ecs_id);
            ebctr.ecs_id = ecs_tbl_row.ecs_id;
            ebctr.house_id = ecs_tbl_row.house_id;
            ebctr.idc_id = "123456";
            ebctr.ecs_id_str = ecs_id_str;
            ebctr.install_dir = "/opt/test";
            ebctr.huge_page = 1024;
            ebctr.rst_interface = "eno2";
            ebctr.rst_mode = "c|s";
            ebctr.upload_Type = "CU";
            ebctr.dpdk_eth_grep = "10G";
            ebctr.rst_dst_mac = secs[13][0] == 0 ? " " : secs[13];
            ebctr.insertRow(ebctr.house_id, ebctr.ecs_id);
        }
    }
    inf.close();
    return 0;
}



void help()
{
    printf( "ecs_import_db \n"
            "\t-i/--import(机房配置规则文件)\n" 
            "\t-d/--db(数据库文件) \n"
            "\t-n/--no_skip(适用于不通过公网IP跳转的情况) \n"
            "规则示例: \n"
            "1234(机房号), 机房名称, 1.1.1.1(公网IP), 10022(公网端口), root, xxx(公网密码明文),"
            " 192.168.11.21, 22(内网起始IP), root, xxx(内网明文), 56(eu数量), 1(起始ECS ID), 2(公网ecs ID), 封堵Mac\n"
        );
}

int main(int argc, char *argv[])
{
    int op_index = 0;
    int c;
    std::string import_file;
    std::string db_file(ecsm::kDefaultEcsDb);

    bool if_skip = true;

    static struct option options[] = {
        {"import",      required_argument, 0, 'i'},
        {"db",          required_argument, 0, 'd'},
        {"help",        no_argument,       0, 'h'},
        {"no_skip",     no_argument,       0, 'n'},
        {0, 0,  0,  0 }
    };

    while (-1 != (c = getopt_long(argc, argv, "i:d:hn", options, &op_index))) {
        switch (c) {
            case 'i':
                import_file.assign(optarg);
                break;            
            case 'd':
                db_file.assign(optarg);
                break;
            case 'h':
                help();
                exit(0);
                break;
            case 'n':
                if_skip = false;
                break;
            default:
                break;
        }
    }

    if (import_file.size() == 0) {
        std::cerr << " use -i/--import {file name} , -d/--db {database}!" << std::endl;
        return 0;
    }

    if (!ecsm::FsUtils::isFileExist(import_file.c_str())) {
        std::cerr << "import file is not exist !" << std::endl;
        return -1;
    }

    SQLite::Database db(db_file, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
    if (ecsm::EcsDB::checkAndCreateTables(db) != 0) {
        return -1;
    }
    if (if_skip) {
        importFile(import_file.c_str(), db);
    } else {
        importFileNoSkip(import_file.c_str(), db);
    }
    return 0;
}
