//
//  Created by zhangm on 2017/3
//

#ifndef _ECS_MANAGER_H_
#define _ECS_MANAGER_H_
#include "ssh2.h"
#include <map>
#include <queue>
#include <string>
#include "SQLiteCpp.h"

namespace ecsm {
    
#define BUF_SIZE 1024

class SshToolCmd
{
public:
    SshToolCmd(std::string host, int port, std::string user, std::string passwd);
    SshToolCmd(SshSessionTuple& sst);
    ~SshToolCmd();
    std::string genCmd(const char *format, ...);
private:
    std::string m_host;
    int m_port;
    std::string m_user;
    std::string m_passwd;
};

enum OpreationCmdType
{
    kSSHExeCmd = 1,
    kSSHSendfile,
    kSSHReceiveFile,
};

struct SSHOpreationCmd
{
    OpreationCmdType type;
    std::string cmd;
};

class SSHOpreation
{
public:
    SSHOpreation(std::string host, int port, std::string user, std::string passwd, int if_remote);
    ~SSHOpreation();
    void addCommand(std::string& cmd, OpreationCmdType type);
    void addCommand(std::string& cmd, OpreationCmdType type, SshToolCmd& stcg);
public:
    void setPublic() {
        if_remote = 0;
    }
    std::vector<SSHOpreationCmd> cmds_;
    SshSessionTuple s_tuple_;
    int if_remote;
    int pure_cmd;
    SshToolCmd* ssh_tool_cmd_;
    std::string log_info;
};

class ECSSessionMap
{
public:
    ECSSessionMap();
    ~ECSSessionMap();
    int add(std::string& ip, int port, ecsm::SshSession* session);
    int add(SshSessionTuple& sTuple, SshSession* session);
    SshSession* findSession(std::string& ip, int port);
    SshSession* findSession(SshSessionTuple& sTuple);
    void destory();
private:
    void genKey(std::string& ip, int port, std::string* key);
    std::map<std::string, ecsm::SshSession*> m_session_map;
};

class ECSManager
{
    typedef std::map<std::string, std::string> ConfigItemMap;
    typedef std::map<std::string, ConfigItemMap> ConfigUpdateMap;

public:
    const static std::string kEcsDbDir;
    const static std::string kUpdateRemoteDir;
    const static std::string kSshTool;
    const static std::string kConfigReplaceTool;
    const static std::string kInstallFile;
    const static std::string kSysdataFile;
    const static std::string kLicenseData;
    const static std::string kDumpFileDir;
public:
    ECSManager();
    ~ECSManager();
    int runQ();
    int addQ(SSHOpreation* sso);
    int fillOpQueueBySQLCmds(const char* sql, std::vector<SSHOpreationCmd>& cmds);
    int simpleTmpPath(std::string& origin_cmd, std::string* tmp_cmd1, std::string* tmp_cmd2);

    int commonExe(SSHOpreation& sso, std::string& cmd, char* stdout_str, int len);
    int commonUpload(SSHOpreation& sso, std::string& cmd_str);
    int commonUpload(SSHOpreation& sso, const char* from, const char* to);
    int updateEXE(std::string& sql, std::string& updateFile);
    int installEXE(std::string& sql, std::string& installFile);
    int uninstallEXE(std::string& sql);
    int gatherSysInfo(std::string& sql);
    int genLicense(std::string& sql, std::string& mode);
    int dumpLicense(std::string& sql, std::string& mode);
    int routingInspection(std::string& sql);
    int configReplace(std::string& sql, std::string& configPair);

    int writeSysData(const char* sn, int cpuNum, const char* cpuModels);
    int localEncodeCmd(const char validTime);
    void readLicenseTime(char *startTime, char *endTime, char validFlag);
    void readLicenseData(char *boardSN, char *cpuNum, char *cpuModel);
private:
    SshSession* getSession(SshSessionTuple& sst);
    int formatPCIaddr(std::string& addr_i, std::string* addr_o);
    std::string licenseStartTime();
    int loadKeyValueFromUpdateConfig(std::string& config_file);
    int genConfigUpdateCommand(std::string& command);
public:
    static std::string getDBDir(void);  
private:
    int ifLogOn;
    std::queue<SSHOpreation*> m_opreation_queue;
    ECSSessionMap m_eusession_map;
    SQLite::Database m_db;
    std::string m_updatefile_path; //the local update file full path
    std::string m_updatefile_name; //the local update file name
    std::string m_ssh_tool_path;   //the local ssh_tool
    ConfigUpdateMap m_config_update;
};


} //end of namespace ecsm

#endif
