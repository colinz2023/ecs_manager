//
//  Created by zhangm on 2017/3
//

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <iostream>
#include <queue>
#include <string>
#include "ssh2.h"
#include "ecs_manager.h"
#include "ecs_db.h"
#include "utils.h"
#include <signal.h>
#include <execinfo.h>

using namespace ecsm;

std::string _Vesroin = ECSM_TOOL_VERSION;
std::string _USAGE = "ecsm_tool 参数:\n"
"  --clause/-C,             SQL选择子句\n"
"  --houseid/--house/-H,    house id\n"
"  --euid/--eu/-E,          eu id\n"
"  --exe/-e,                执行命令\n"
"  --upload/--ul/-U,        上传文件\n"
"  --download/--dl/-D,      下载文件\n\n"
"  --update/-u,             升级 [安装文件路径]\n"
"  --install/-i,            安装 [安装文件路径]\n"
"  --remove/-r,             卸载 \n"
"  --config/-g,             更新配置 [配置更新文件]\n\n"
"  --collect/-c,            收集机器信息\n"
"  --auth/-a,               安装License [t/o/f]\n"
"  --dump_license/-d,       导出License数据 [t/o/f], 导出System_data数据 [s]\n"
"  --routing_inspection/-R, 巡检\n\n"
"  --version/-v,            工具版本\n"
"  --help/-h,               帮助\n"
"例如: \n"
"1.通过ssh远程执行cpaccess, 查看机房91014至91015, ECS 1和ECS 2的 版本 \n"
" # ./ecsm_tool --houseid=91014-91015 --euid=1,2 --exe=\"cpaccess --cmd=version\" \n\n"
"2.通过config.update配置更新文件, 更新机房91014的 配置文件 \n"
" # ./ecsm_tool --houseid=91014 -g config.update \n\n"
"3.将本机的目录的/home/mydata.txt文件上传到指定的ECS, 生成文件/opt/data.txt \n"
" # ./ecsm_tool --houseid 91014 --euid 1 --upload=/home/mydata.txt:/opt/data.txt \n"
;

std::string FLAGS_clause = "";
std::string FLAGS_houseids = "";
std::string FLAGS_euids = "";
std::string FLAGS_exe = "";
std::string FLAGS_upload = "";
std::string FLAGS_download = "";
std::string FLAGS_auth = "";

std::string FLAGS_configUpdateFile= "";
std::string FLAGS_updateFile = "";


struct EcsmToolIntPara
{
    std::vector<int> para_sec;
    std::vector<int> para_seq;
    std::string para_seq_str;
    int sec_num;
    int seq_num;
    EcsmToolIntPara() {
        sec_num = 0;
        seq_num = 0;
        para_seq_str = "";
    }
};

//危险!!!
char g_not_support_[][128] = {
};

char g_not_support_cmd[][128] = {
    "dd",
    "yum",
    "fdisk",
    "alias",
};

static int check_if_no_support(std::string& cmd)
{
    int i = 0;
    for (i = 0; i < sizeof(g_not_support_) / sizeof(g_not_support_[0]); i++) {
        if (strspn(g_not_support_[i], cmd.c_str()) == strlen(g_not_support_[i])) {
            return 1;
        }
    }
    for (i = 0; i < sizeof(g_not_support_cmd) / sizeof(g_not_support_cmd[0]); i++) {
        if (0 == strncmp(g_not_support_cmd[i], cmd.c_str(), strlen(g_not_support_cmd[i]))) {
            return 1;
        }
    }
    return 0;
}

/*
* return 0 is error
*/
static int parseParamter(std::string& param_str, EcsmToolIntPara* etip)
{
    int len = param_str.size(); 
    if (0 == len) return 1;
    const char* param = param_str.c_str();
    int i;
    int di = -1;
    char buff[1024];
    char old = 0;
    for (i = 0; i < len; i++) {
        char c = *(param + i);
        int j = 1;
        memset(buff, 0, sizeof buff);
        if (!isdigit(c) && 
            c != ',' && 
            c!= '-') {
            return 0;
        }
        if (c == ',' || c == '-') {
            char cc = *(param + i + j);
            if (cc == ',' || cc == '-') {
                return 0;
            } else {
                if (di == -1) return 0;
                memcpy(buff, (char*)param+di, i - di);
                if (c == '-' || old == '-') {
                    etip->para_sec.push_back(atoi(buff));
                } else {
                    etip->para_seq.push_back(atoi(buff));
                }
                di = -1;
                old = c;
            }
        } else {
            if (di == -1) {
                di = i; 
            }
        }
    }
    if (di == -1) return 0;
    memcpy(buff, (char*)param+di, len - di);
    if ('-' == old) {
        etip->para_sec.push_back(atoi(buff));
    } else {
        etip->para_seq.push_back(atoi(buff));
    }
    etip->sec_num = etip->para_sec.size();
    if (etip->sec_num % 2) {
        return 0;
    }
    etip->seq_num = etip->para_seq.size();
    for (std::vector<int>::iterator v = etip->para_seq.begin(); v != etip->para_seq.end(); v++) {
        char buff[64];
        snprintf(buff, sizeof buff, "%d,", *v);
        etip->para_seq_str.append(buff);
    }
    etip->para_seq_str.erase(etip->para_seq_str.find_last_not_of(", \t\n\r") + 1);
    return 1;
}

void backtrace_print(int sig_num)
{
    int i = 0;
    void* buffer[100] = {0};
    int n = backtrace(buffer, 100);
    char** symbols = (char**)backtrace_symbols(buffer, n);

    std::cout << strsignal(sig_num) << std::endl;

    if (symbols != NULL) {
        for(i = 0; i < n; i++) {
            std::cout << buffer[i] << ":" << symbols[i] << std::endl;
        }
    }
    exit(-1);
}

void siginit(void)
{
    signal(SIGSEGV, backtrace_print);
    signal(SIGFPE, backtrace_print);
    signal(SIGILL, backtrace_print);
    signal(SIGBUS, backtrace_print);
    signal(SIGABRT, backtrace_print);
}

int main(int argc, char *argv[])
{    
    int opt = 0;
    int rc = 0;
    int cmd_count = 0;
    int op_cmd_count = 0;
    bool desc_order = false;
    const int kCmdCountMax = 20;
    LibSsh2::init();
    std::vector<SSHOpreationCmd> opCmds;
    SSHOpreationCmd cmd;

    if (argc == 1) {
        std::cout << _USAGE << std::endl;
        exit(0);
    }

    while (1) {
        int option_index = 0;
        int c = 0;
        static struct option long_options[] = {
            {"clause",      required_argument, 0, 'C'},
            {"houseid",     required_argument, 0, 'H'},
            {"hid",         required_argument, 0, 'H'},
            {"house",       required_argument, 0, 'H'},
            {"euid",        required_argument, 0, 'E'},
            {"eid",         required_argument, 0, 'E'},
            {"eu",          required_argument, 0, 'E'},
            {"exe",         required_argument, 0, 'e'},
            {"upload",      required_argument, 0, 'U'},
            {"ul",          required_argument, 0, 'U'},
            {"download",    required_argument, 0, 'D'},
            {"dl",          required_argument, 0, 'D'},
            {"update",      required_argument, 0, 'u'},
            {"install",     required_argument, 0, 'i'},
            {"config",      required_argument, 0, 'g'},
            {"remove",      no_argument,       0, 'r'},
            {"auth",        required_argument, 0, 'a'},
            {"collect",     no_argument,       0, 'c'},
            {"dump_license",required_argument, 0, 'd'},
            {"routing_inspection",no_argument, 0, 'R'},
            {"help",        no_argument,       0, 'h'},
            {"version",     no_argument,       0, 'v'},
            {0,             0,                 0,  0 }
        };
        c = getopt_long(argc, argv, "rC:E:H:e:u:d:hv0:1:2:a:ci:D:U:d:Rg:", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 'C':
                FLAGS_clause.assign(optarg);
                break;            
            case 'E':
                FLAGS_euids.assign(optarg);
                break;
            case 'H':
                FLAGS_houseids.assign(optarg);
                break;
            case 'e':
                FLAGS_exe.assign(optarg);
                StringUtils::Trim(FLAGS_exe);
                if (0 == FLAGS_exe.find("reboot")) {
                    desc_order = true;
                }
                //注意!!!!
                if (check_if_no_support(FLAGS_exe)) {
                    std::cerr << "not support command !" << std::endl;
                    return -1;
                }
                cmd.cmd  = FLAGS_exe;
                cmd.type = kSSHExeCmd;
                opCmds.push_back(cmd);
                op_cmd_count++;
                break;            
            case 'U':
                FLAGS_upload.assign(optarg);
                cmd.cmd  = FLAGS_upload;
                cmd.type = kSSHSendfile;
                opCmds.push_back(cmd);
                op_cmd_count++;
                break;           
            case 'D':
                FLAGS_download.assign(optarg);
                cmd.cmd  = FLAGS_download;
                cmd.type = kSSHReceiveFile;
                opCmds.push_back(cmd);
                op_cmd_count++;
                break;
            case 'h':
                std::cout << "ecsm_tool, " << _Vesroin << std::endl;
                std::cout << _USAGE << std::endl;
                cmd_count++;
                return 0;
            case 'v':
                std::cout << _Vesroin << std::endl;
                cmd_count++;
                return 0;
                break;
            case 'i':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_updateFile.assign(optarg);
                }
                break;
            case 'u':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_updateFile.assign(optarg);
                }
                break;            
            case 'g':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_configUpdateFile.assign(optarg);
                }
                break;
            case 'r':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_updateFile.assign(optarg);
                }
                break;
            case 'a':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_auth.assign(optarg);
                }
                break;            
            case 'd':
                opt = c;
                cmd_count++;
                if (NULL != optarg) {
                    FLAGS_auth.assign(optarg);
                }
                break;
            case 'c':
                opt = c;
                cmd_count++;
                break;
            case 'R':
                opt = c;
                cmd_count++;
                break;
            default:
                break;   
        }
    }

    if (op_cmd_count >= kCmdCountMax || cmd_count > 1 || (cmd_count > 0 && op_cmd_count > 0) ) {
        std::cerr << "Parameter error or too much parameter !" << std::endl;
        return -1;
    }

    std::string sql_str = "SELECT * from " + kEcsTable + " ";
    if (FLAGS_clause.size() == 0) {
        EcsmToolIntPara houseid_param;
        EcsmToolIntPara euid_param;
        
        if (!parseParamter(FLAGS_houseids, &houseid_param)) {
            std::cerr << "houseid not right" << std::endl;  
            return -1;
        }

        if (!parseParamter(FLAGS_euids, &euid_param)) {
            std::cerr << "euid not right" << std::endl;  
            return -1;
        }
        std::string sql_clause = "";
        char buff[1024];
        int i;
        if (houseid_param.seq_num + houseid_param.sec_num > 0) {
            sql_clause.append(" where (");
            i = 0;
            while (houseid_param.sec_num) {
                if (i == 0) {
                    snprintf(buff, sizeof buff, " house_id BETWEEN %d and %d "
                            , houseid_param.para_sec[i], houseid_param.para_sec[i + 1]);
                } else {
                    snprintf(buff, sizeof buff, " or house_id BETWEEN %d and %d "
                            , houseid_param.para_sec[i], houseid_param.para_sec[i + 1]);
                }
                i += 2;
                houseid_param.sec_num -= 2;
                sql_clause.append(buff);
            }
            if (houseid_param.seq_num) {
                if (i > 0) {
                    sql_clause.append(" or ");
                }
                snprintf(buff, sizeof buff, "house_id in (%s) ", houseid_param.para_seq_str.c_str());
                sql_clause.append(buff);
            }
            sql_clause.append(") ");
        }

        if (euid_param.seq_num + euid_param.sec_num > 0) {
            if (sql_clause.size() > 0) {
                sql_clause.append(" and ");
            }
            sql_clause.append(" (");
            i = 0;
            while (euid_param.sec_num) {
                if (i == 0) {
                    snprintf(buff, sizeof buff, " ecs_id BETWEEN %d and %d ", 
                        euid_param.para_sec[i], euid_param.para_sec[i + 1]);
                } else {
                    snprintf(buff, sizeof buff, " or ecs_id BETWEEN %d and %d ", 
                        euid_param.para_sec[i], euid_param.para_sec[i + 1]);
                }
                i += 2;
                euid_param.sec_num -= 2;
                sql_clause.append(buff);
            }
            if (euid_param.seq_num) {
                if (i > 0) {
                    sql_clause.append(" or ");
                }
                snprintf(buff, sizeof buff, "ecs_id in (%s) ", euid_param.para_seq_str.c_str());
                sql_clause.append(buff);
            }
            sql_clause.append(")");
        }
        sql_str += sql_clause;
    } else {
        sql_str += FLAGS_clause;
    }

    ECSManager ecs_manager;
    if (opCmds.size() > 0) {
        if (desc_order) {
            sql_str += "ORDER BY ecs_id DESC";
        }
        ecs_manager.fillOpQueueBySQLCmds(sql_str.c_str(), opCmds);
        ecs_manager.runQ();
    } else {
         switch (opt) {
            case 'u':
                ecs_manager.updateEXE(sql_str, FLAGS_updateFile);
                break;
            case 'i':
                ecs_manager.installEXE(sql_str, FLAGS_updateFile);
                break;
            case 'r':
                ecs_manager.uninstallEXE(sql_str);
                break;
            case 'a':
                ecs_manager.genLicense(sql_str, FLAGS_auth);
                break;
            case 'd':
                ecs_manager.dumpLicense(sql_str, FLAGS_auth);
                break;
            case 'c':
                ecs_manager.gatherSysInfo(sql_str);
                break;
            case 'g':
                ecs_manager.configReplace(sql_str, FLAGS_configUpdateFile);
                break;
            case 'R':
                ecs_manager.routingInspection(sql_str);
                break;
            default:
                return 0; 
         }
    }
    return 0;
}
