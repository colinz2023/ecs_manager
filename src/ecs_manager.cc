//
//  Created by zhangm on 2017/3
//

#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <map>
#include <utility>
#include <iostream>
#include <sstream>
#include <fstream>

#include "ssh2.h"
#include "utils.h"
#include "ecs_db.h"
#include "ecs_manager.h"
#include "log.h"

namespace ecsm {

static const std::string kRmCSMS = \
"systemctl stop csms.service;"
"systemctl stop cpftp_download.service;"
"systemctl stop cpftp_upload_cu.service;"
"systemctl stop dpdk-init.service;"
"systemctl disable csms.service;"
"systemctl disable cpftp_download.service;"
"systemctl disable cpftp_upload_cu.service;"
"systemctl disable dpdk-init.service;"
"rm -f /usr/lib/systemd/system/csms.service;"
"rm -f /usr/lib/systemd/system/cpftp_download.service;"
"rm -f /usr/lib/systemd/system/cpftp_upload_cu.service;"
"rm -f /usr/lib/systemd/system/dpdk-init.service";

const std::string ECSManager::kEcsDbDir = "";
const std::string ECSManager::kUpdateRemoteDir = "/tmp";
const std::string ECSManager::kSshTool = "ssh_tool";
const std::string ECSManager::kConfigReplaceTool = "config_replace";
const std::string ECSManager::kInstallFile = "setup_release";
const std::string ECSManager::kSysdataFile = "system_data";
const std::string ECSManager::kLicenseData = "encode_data";
const std::string ECSManager::kDumpFileDir = "dump_file";

ECSSessionMap::ECSSessionMap()
{

}

ECSSessionMap::~ECSSessionMap()
{
    destory();
}

void ECSSessionMap::genKey(std::string& ip, int port, std::string* key)
{
    char port_str[16];
    snprintf(port_str, sizeof port_str, "%d", port);
    key->assign(ip + port_str);
}

void ECSSessionMap::destory()
{
    std::map<std::string, ecsm::SshSession*>::iterator it;
    for (it = m_session_map.begin(); it != m_session_map.end(); it++) {
        delete it->second;
    }
    m_session_map.clear();
}

int ECSSessionMap::add(std::string& ip, int port, SshSession* session)
{
    std::string key;
    genKey(ip, port, &key);
    m_session_map.insert(std::pair<std::string, SshSession*>(key, session));
    return 0;
}

int ECSSessionMap::add(SshSessionTuple& sTuple, SshSession* session)
{
    std::string key = sTuple.genKey();
    m_session_map.insert(std::pair<std::string, SshSession*>(key, session));
    return 0;
}

SshSession* ECSSessionMap::findSession(std::string& ip, int port)
{
    std::map<std::string, ecsm::SshSession*>::iterator it;
    std::string key;
    genKey(ip, port, &key);
    it = m_session_map.find(key);
    if (it == m_session_map.end()) {
        return NULL;
    }
    return it->second;
}

SshSession* ECSSessionMap::findSession(SshSessionTuple& sTuple)
{
    std::map<std::string, ecsm::SshSession*>::iterator it;
    std::string key = sTuple.genKey();
    it = m_session_map.find(key);
    if (it == m_session_map.end()) {
        return NULL;
    }
    return it->second;
}

SshToolCmd::SshToolCmd(std::string host, int port, std::string user, std::string passwd)
{
    m_host = host;
    m_port = port;
    m_user = user;
    m_passwd = passwd;
}

SshToolCmd::SshToolCmd(SshSessionTuple& sst)
{
    m_host = sst.m_host;
    m_port = sst.m_port;
    m_user = sst.m_user;
    m_passwd = sst.m_passwd;
}

SshToolCmd::~SshToolCmd()
{

}

std::string SshToolCmd::genCmd(const char *format, ...)
{
    char buf[20480] = {0};
    char str[10240] = {0};
    va_list ap;
    va_start(ap, format);
    vsnprintf(str, sizeof str, format, ap);
    va_end(ap);

    snprintf(buf, sizeof buf, "%s/%s -H %s -P %d -u %s -p %s %s",
            ECSManager::kUpdateRemoteDir.c_str(), 
            ECSManager::kSshTool.c_str(),
            m_host.c_str(),
            m_port,
            m_user.c_str(),
            m_passwd.c_str(),
            str);
    return std::string(buf);
}

std::string ECSManager::getDBDir(void)
{
    if (ECSManager::kEcsDbDir.length() > 0) {
        return ECSManager::kEcsDbDir + "/" + kDefaultEcsDb;
    } 
    char* dir = getenv("ECSDB_DIR");
    if (NULL == dir) {
        char cwd[512] = {0};
        std::string a = std::string(getcwd(cwd, sizeof cwd));
        return a + "/" + kDefaultEcsDb; 
    }
    std::string aa(dir);
    return aa + "/" + kDefaultEcsDb;
}

SSHOpreation::SSHOpreation(std::string host, int port, std::string user, std::string passwd, int if_remote)
    :s_tuple_(host, port, user, passwd)
{
    this->if_remote = if_remote;
    this->pure_cmd = 0;
}

SSHOpreation::~SSHOpreation()
{
    if (NULL != ssh_tool_cmd_) {
        delete ssh_tool_cmd_;
    }
}

void SSHOpreation::addCommand(std::string& cmd, OpreationCmdType type)
{
    SSHOpreationCmd soc;
    soc.type = type;
    soc.cmd = cmd;
    cmds_.push_back(soc);
}

// not used
void SSHOpreation::addCommand(std::string& cmd, OpreationCmdType type, SshToolCmd& stcg)
{
    SSHOpreationCmd soc;
    soc.type = type;
    if (this->if_remote) {
        if (soc.type == kSSHExeCmd) {
            soc.cmd = stcg.genCmd("--cmd=\"%s\"", cmd.c_str());
        } else if (soc.type == kSSHSendfile) {
            soc.cmd = stcg.genCmd("--scp_s=\"%s\"", cmd.c_str());
        } else if (soc.type == kSSHReceiveFile) {
            soc.cmd = stcg.genCmd("--scp_r=\"%s\"", cmd.c_str());
        }
    } else {
        soc.cmd = cmd;
    }
    cmds_.push_back(soc);
}

ECSManager::ECSManager() 
    :m_db(getDBDir(), SQLite::OPEN_READWRITE), ifLogOn(1)
{
    char* dir = getenv("ECSM_UPDATE_FILE");
    if (NULL == dir) {
        m_updatefile_path = kInstallFile;
    } else {
        m_updatefile_path = std::string(dir);
    }

    if (NULL != getenv("ECSM_NO_LOG")) {
        ifLogOn = 0;
    }
    StringUtils::GetFileNameByPath(m_updatefile_path, &m_updatefile_name);
    m_ssh_tool_path = std::string("./");
    m_ssh_tool_path.append(kSshTool);
    //std::cout << "m_updatefile_path=" << m_updatefile_path << std::endl;
    //std::cout << "m_updatefile_name=" << m_updatefile_name << std::endl;
}

ECSManager::~ECSManager()
{
    std::cout << ANSI_COLOR_RESET;
}

int ECSManager::simpleTmpPath(std::string& origin_cmd, std::string* tmp_cmd1, std::string* tmp_cmd2)
{
    std::string::size_type n = origin_cmd.find_first_of(":");
    if (n == std::string::npos) {
        return -1;
    }
    std::string path_from = origin_cmd.substr(0, n);
    std::string path_send = origin_cmd.substr(n + 1, origin_cmd.size());

    std::string send_to_filename;
    StringUtils::GetFileNameByPath(path_send, &send_to_filename);
    std::string tmp_path = kUpdateRemoteDir + "/" + send_to_filename;

    tmp_cmd1->assign(path_from + ":" + tmp_path);
    tmp_cmd2->assign(tmp_path + ":" + path_send);
    return 0;
}

SshSession* ECSManager::getSession(SshSessionTuple& sst)
{
    SshSession* session = NULL;
    if (NULL == (session = m_eusession_map.findSession(sst))) {
        session = LibSsh2::newSeesion(sst, 12*1000);
        if (NULL != session) {
            m_eusession_map.add(sst, session);
        } 
    }
    return session;
}

int ECSManager::addQ(SSHOpreation* sso)
{
    m_opreation_queue.push(sso);
    return 0;
}

int ECSManager::runQ()
{
    int rc = 0;
    std::string cmds;
    while (m_opreation_queue.size() > 0) {
        SSHOpreation* sso = m_opreation_queue.front();
        if (ifLogOn) {
            std::cout << ANSI_COLOR_GREEN;
            std::cout << sso->log_info << std::endl;
            std::cout << ANSI_COLOR_RESET;
        }
        SshSession* session = getSession(sso->s_tuple_);
        if (NULL == session) {
            std::cout << "session is NULL, continue" << std::endl;
            m_opreation_queue.pop();
            continue;
        }

        std::vector<SSHOpreationCmd>::iterator it = sso->cmds_.begin();
        for (; it != sso->cmds_.end(); it++)
        {
            if (sso->if_remote) 
            {
                if (sso->pure_cmd) {
                    cmds.append(" --cmd=");
                    cmds.append("\"");
                    cmds.append(it->cmd.c_str());
                    cmds.append("\"");
                    std::string remote_ssh_tool = kUpdateRemoteDir + "/" + kSshTool;
                    session->sendFile(m_ssh_tool_path, remote_ssh_tool);
                } else {
                    std::string remote_ssh_tool = kUpdateRemoteDir + "/" + kSshTool;
                    session->sendFile(m_ssh_tool_path, remote_ssh_tool);
                    if (it->type == kSSHExeCmd) {
                        std::string cmd_str = sso->ssh_tool_cmd_->genCmd("--cmd=\"%s\"", it->cmd.c_str());
                        rc = session->exeCommand(cmd_str);
                    } else if (it->type == kSSHSendfile) {
                        std::string tmp_cmd1;
                        std::string tmp_cmd2;
                        simpleTmpPath(it->cmd, &tmp_cmd1, &tmp_cmd2);
                        rc = session->sendFile(tmp_cmd1);
                        if (rc != 0) {
                            break;
                        }
                        std::string sendfile_str = sso->ssh_tool_cmd_->genCmd("--scp_s=\"%s\"", tmp_cmd2.c_str());
                        rc = session->exeCommand(sendfile_str);
                        //std::cout << "runQ, cmd:" << it->cmd << std::endl;
                    } else if (it->type == kSSHReceiveFile) {
                        std::string tmp_cmd1;
                        std::string tmp_cmd2;
                        simpleTmpPath(it->cmd, &tmp_cmd1, &tmp_cmd2);

                        std::string receivefile_str = sso->ssh_tool_cmd_->genCmd("--scp_r=\"%s\"", tmp_cmd1.c_str());
                        rc = session->exeCommand(receivefile_str);
                        if (rc != 0) {
                            break;
                        }
                        rc = session->receiveFile(tmp_cmd2);
                    }
                }
            } 
            else 
            {
                if (it->type == kSSHExeCmd) {
                    rc = session->exeCommand(it->cmd);
                    //std::cout << "runQ, cmd:" << it->cmd << std::endl;
                } else if (it->type == kSSHSendfile) {
                    rc = session->sendFile(it->cmd);
                    //std::cout << "runQ, cmd:" << it->cmd << std::endl;
                } else if (it->type == kSSHReceiveFile) {
                    rc = session->receiveFile(it->cmd);
                    //std::cout << "runQ, cmd:" << it->cmd << std::endl;
                }
            }
            if (rc != 0) {
                session->lastError();
                break;
            }
        }

        if (sso->pure_cmd && sso->if_remote) {
            std::string cmds_str = sso->ssh_tool_cmd_->genCmd("%s", cmds.c_str());
            rc = session->exeCommand(cmds_str);
             if (rc != 0) {
                session->lastError();
            }
        }
        cmds = "";
        m_opreation_queue.pop();
        if (!ifLogOn) {
            std::cout << std::endl;
        }
        delete sso;
    }
    return rc;
}

int ECSManager::fillOpQueueBySQLCmds(const char* sql, std::vector<SSHOpreationCmd>& cmds)
{
    if (cmds.size() == 0) {
        return 0;
    }
    char buf[256];
    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    while (query.executeStep()) {
        euRow.getRow(query);
        //not public 
        SSHOpreation* sso = new SSHOpreation(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
        sso->ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);
        sso->pure_cmd = 1;
        snprintf(buf, sizeof buf, "On house[%d](%s),eu[%d],ip[%s]", euRow.house_id, euRow.site_name.c_str(), euRow.ecs_id, euRow.lan_ip.c_str());
        sso->log_info.assign(buf);
        for (std::vector<SSHOpreationCmd>::iterator it = cmds.begin(); it != cmds.end(); it++) {
            sso->addCommand(it->cmd, it->type);
            if (it->type == kSSHSendfile || it->type == kSSHReceiveFile) {
                sso->pure_cmd = 0;
            }
        }
        this->addQ(sso);
    }
    return 0;
}

int ECSManager::commonExe(SSHOpreation& sso, std::string& cmd, char* stdout_str, int len)
{
    SshSession* session = getSession(sso.s_tuple_);
    if (NULL == session) {
        std::cout << "session is NULL " << std::endl;
        return -1;
    }
    std::string cmd_str;
    if (sso.if_remote) {
        std::string remote_ssh_tool = kUpdateRemoteDir + "/" + kSshTool;
        session->sendFile(m_ssh_tool_path, remote_ssh_tool);
        cmd_str = sso.ssh_tool_cmd_->genCmd("--cmd=\"%s\"", cmd.c_str());
    } else {
        cmd_str = cmd;
    }
    memset(stdout_str, 0, len);
    return  session->exeCommandWithStdout(cmd_str.c_str(), stdout_str, len);
}

int ECSManager::commonUpload(SSHOpreation& sso, std::string& cmd_str)
{
    int rc = 0;
    std::string tmp_cmd1;
    std::string tmp_cmd2;

    SshSession* session = getSession(sso.s_tuple_);
    if (NULL == session) {
        std::cout << "session is NULL " << std::endl;
        return -1;
    }
    if (sso.if_remote) {
        std::string remote_ssh_tool = kUpdateRemoteDir + "/" + kSshTool;
        session->sendFile(m_ssh_tool_path, remote_ssh_tool);
        simpleTmpPath(cmd_str, &tmp_cmd1, &tmp_cmd2);
        rc = session->sendFile(tmp_cmd1);
        if (rc != 0) {
            return -1;
        }
        std::string sendfile_str = sso.ssh_tool_cmd_->genCmd("--scp_s=\"%s\"", tmp_cmd2.c_str());
        rc = session->exeCommand(sendfile_str);
    } else {
        rc = session->sendFile(cmd_str);
    }
    return rc;
}

int ECSManager::commonUpload(SSHOpreation& sso, const char* from, const char* to)
{
    std::string cmd_str;
    cmd_str += from;
    cmd_str += ":";
    cmd_str += to;
    return commonUpload(sso, cmd_str);
}

int ECSManager::gatherSysInfo(std::string& sql)
{
    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    char buff[4096];
    int rc = 0;
    int cnt = 0;

    while (query.executeStep()) {
        euRow.getRow(query);
        //not public 
        SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
        sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);

        EcsMachineInfoTblRow mir(&m_db);
        EcsBasicConfigTblRow bcr(&m_db);
        std::cout << ANSI_COLOR_GREEN << "[" << ++cnt << "]" << ANSI_COLOR_RESET;
        std::cout << "collect machine info on, " << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;

        std::string _cmdHostname = "hostname";
        rc = commonExe(sso, _cmdHostname, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        mir.hostname = buff;
        StringUtils::Trim(mir.hostname);
        
        std::string _cmdCpuModel = "cat /proc/cpuinfo | grep 'model name' | cut -f2 -d:| sed 's/^[ \t]*//g'";
        rc = commonExe(sso, _cmdCpuModel, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        mir.cpu_modles = buff;
        StringUtils::Trim(mir.cpu_modles);

        std::string _cmdCpuNum = "cat /proc/cpuinfo | grep processor | wc -l";
        rc = commonExe(sso, _cmdCpuNum, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        mir.cpu_number = atoi(buff);
      
        std::string _cmdBoardSerial = "dmidecode -t 2 |grep 'Serial Number' | cut -f2 -d:";
        rc = commonExe(sso, _cmdBoardSerial, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        mir.board_serial = buff;
        StringUtils::Trim(mir.board_serial);
       
        bcr.getRow(euRow.house_id, euRow.ecs_id);
        std::string _cmdLscpi = "lspci | grep " + bcr.dpdk_eth_grep + " | cut -f1 -d' ' | tr '\n' ' '";
        rc = commonExe(sso, _cmdLscpi, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        mir.eth_pci_addr = buff;

        mir.id = euRow.id;
        mir.house_id = euRow.house_id;
        mir.ecs_id = euRow.ecs_id;
        mir.insertRow(euRow.house_id, euRow.ecs_id);
    }
    return 0;
}

int ECSManager::genLicense(std::string& sql, std::string& mode)
{
    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    char buff[4096];
    int rc = 0;
    char cmode = mode.size() > 0 ? mode[0] : 't';

    FsUtils::mkDir("output");
    if (!FsUtils::isFileExist("output/licensed.conf")) {
        FILE* f = fopen("output/licensed.conf", "w");
        if (NULL != f) {
            fprintf(f, "%s%s\n%s\n%s\n",
                "starttime=",
                licenseStartTime().c_str(),
                "deskey=jksdfsl;ja;fklsafa;sl;jf",
                "desfilekey=kdskjffakdsfalf;ajsjf;");
            fclose(f);
        }
    }

    if (!FsUtils::isFileExist("./licensed")) {
        std::cout << ANSI_COLOR_RED;
        std::cout << "No supported!" << std::endl;
        std::cout << ANSI_COLOR_RESET;
        return 1;
    }

    while (query.executeStep()) {
        euRow.getRow(query);
        EcsBasicConfigTblRow bcr(&m_db);
        SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
        sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);
        
        std::cout << ANSI_COLOR_GREEN;
        std::cout << "license authentication on," << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
        std::cout << ANSI_COLOR_RESET;

        EcsMachineInfoTblRow mir(&m_db);
        bcr.getRow(euRow.house_id, euRow.ecs_id);
        mir.getRow(euRow.house_id, euRow.ecs_id);

        if (bcr.id <= 0 || mir.id <= 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "not data" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }

        rc = writeSysData(mir.board_serial.c_str(), mir.cpu_number, mir.cpu_modles.c_str()); 
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on , writeSysData" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        rc = localEncodeCmd(cmode);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on, localEncodeCmd" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }

        std::string licenseFile = "output/" + kLicenseData;
        std::string remoteLicenseFile = bcr.install_dir + "/" + "config/" + kLicenseData;
        rc = commonUpload(sso, licenseFile.c_str(), remoteLicenseFile.c_str());
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on, commonUpload" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }

        sso.setPublic();
        std::string rmTmplicenseFile = "rm -f " + kUpdateRemoteDir + "/" + kLicenseData;
        rc = commonExe(sso, rmTmplicenseFile, buff, sizeof buff);
        if (rc != 0) {
            continue;
        }
    }
    return 0;
}

int ECSManager::dumpLicense(std::string& sql, std::string& mode)
{
    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    int rc = 0;
    bool sysdata_only = false;
    char cmode = mode.size() > 0 ? mode[0] : 't';

    //t/o/f s
    if (mode[0] == 's') {
        sysdata_only = true;
    } else if (mode[0] != 't' && mode[0] != 'o' && mode[0] != 'f') {
        std::cout << ANSI_COLOR_RED;
        std::cout << "invalid parameter!" << std::endl;
        return -1;
        std::cout << ANSI_COLOR_RESET;
    }

    FsUtils::mkDir("output");
    if (!FsUtils::isFileExist("output/licensed.conf")) {
        FILE* f = fopen("output/licensed.conf", "w");
        if (NULL != f) {
            fprintf(f, "%s%s\n%s\n%s\n",
                "starttime=",
                licenseStartTime().c_str(),
                "deskey=jksdfsl;ja;fklsafa;sl;jf",
                "desfilekey=kdskjffakdsfalf;ajsjf;");
            fclose(f);
        }
    }

    if (!FsUtils::isFileExist("./licensed") && !sysdata_only) {
        std::cout << ANSI_COLOR_RED;
        std::cout << "No supported!" << std::endl;
        std::cout << ANSI_COLOR_RESET;
        return 1;
    }

    FsUtils::EnsureDirectory(kDumpFileDir);
    //FsUtils::RemoveAllFiles(kDumpFileDir);

    std::cout << ANSI_COLOR_GREEN;
    std::cout << "system_data dir : " << kDumpFileDir << std::endl;
    if (!sysdata_only) {
    std::cout << "license dir     : " << kDumpFileDir << std::endl;
    }
    std::cout << ANSI_COLOR_RESET;

    while (query.executeStep()) {
        char cmd[2048];
        std::string sysdatafile = "output/" + kSysdataFile;
        std::string licenseFile = "output/" + kLicenseData;

        euRow.getRow(query);
        EcsBasicConfigTblRow bcr(&m_db);

        std::string real_dump_dir = kDumpFileDir + "/" + StringUtils::itos(euRow.house_id);
        FsUtils::EnsureDirectory(real_dump_dir);
        
        std::string sysdataDestfile = real_dump_dir + "/" + euRow.lan_ip + "_" + kSysdataFile;
        std::string licenseDestFile = real_dump_dir + "/" + euRow.lan_ip + "_" + kLicenseData;

        std::cout << ANSI_COLOR_GREEN;
        std::cout << "Dumping  house_id:" << euRow.house_id << ", ecs_id:" << euRow.ecs_id << ", ";
        std::cout << "system_data: " << sysdataDestfile;
        if (!sysdata_only) {
            std::cout << ", license: " << licenseDestFile << std::endl;
        } else {
            std::cout << std::endl;
        }
        std::cout << ANSI_COLOR_RESET;

        EcsMachineInfoTblRow mir(&m_db);
        bcr.getRow(euRow.house_id, euRow.ecs_id);
        mir.getRow(euRow.house_id, euRow.ecs_id);

        if (bcr.id <= 0 || mir.id <= 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "not data" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }

        rc = writeSysData(mir.board_serial.c_str(), mir.cpu_number, mir.cpu_modles.c_str()); 
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "Error occur on , writeSysData" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
        snprintf(cmd, sizeof cmd, "cp -af %s %s", sysdatafile.c_str(), sysdataDestfile.c_str());
        system(cmd);

        if (!sysdata_only) {
            rc = localEncodeCmd(cmode);
            if (rc != 0) {
                std::cout << ANSI_COLOR_RED;
                std::cout << "Error occur on, localEncodeCmd" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
                std::cout << ANSI_COLOR_RESET;
                continue;
            }
            snprintf(cmd, sizeof cmd, "cp -af %s %s", licenseFile.c_str(), licenseDestFile.c_str());
            system(cmd);
        }
    }
    return 0;
}

int ECSManager::loadKeyValueFromUpdateConfig(std::string& config_file)
{
    if (config_file.size() == 0) {
        return 0;
    }
    std::ifstream updateFileStream(config_file.c_str());
    char line[2048];
    if (!updateFileStream.good()) {
        printf("cat not open : %s \n", config_file.c_str());
        return -1;
    }
    std::string file_name;
    while (1) {
        updateFileStream.getline(line, sizeof(line));
        //文件流结束或错误,退出
        if (updateFileStream.eof() || !updateFileStream.good()) break;
        std::string lineStr = std::string(line);
        std::string configKey;
        std::string configValue;
        if (StringUtils::splitByDelimiter(lineStr, configKey, configValue, '=') == 0) {
            StringUtils::Trim(configKey);
            StringUtils::Trim(configValue);
            if (configKey.size() > 0 && configKey[0] != '#') {
                m_config_update[file_name][configKey] = configValue;        
            }
        } else {
            StringUtils::Trim(lineStr);
            if (lineStr.size() > 0 && lineStr[0] != '#') {
                file_name = lineStr;
            }
        }
    }
    updateFileStream.close();
    return 0;
}

// " --kv eu.conf:euconf.idcid=%s "
int ECSManager::genConfigUpdateCommand(std::string& command)
{
    ConfigUpdateMap::iterator iter;
    ConfigItemMap::iterator iter_kv;
    
    iter = m_config_update.begin();
    for ( ; iter != m_config_update.end(); iter++) {
        iter_kv = iter->second.begin();
        for (; iter_kv != iter->second.end(); iter_kv++) {
            command.append(" --kv=");
            command.append("\"");
            command.append(iter->first);
            command.append(":");
            command.append(iter_kv->first);
            command.append("=");
            command.append(iter_kv->second);
            command.append("\"");
        }
    }
    return 0;
}

int ECSManager::configReplace(std::string& sql, std::string& configPair)
{
    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    char buff[4096] = {0};
    int rc = 0;

    if (!FsUtils::isFileExist(configPair.c_str())) {
        std::cout << ANSI_COLOR_RED;
        std::cout << configPair << " not exist " << std::endl;
        std::cout << ANSI_COLOR_RESET;
        return -1;
    }

    loadKeyValueFromUpdateConfig(configPair);
    
    while (query.executeStep()) {
        euRow.getRow(query);
        EcsBasicConfigTblRow bcr(&m_db);
        SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
        sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);
        bcr.getRow(euRow.house_id, euRow.ecs_id);
        
        std::cout << ANSI_COLOR_GREEN;
        std::cout << "edit config on," << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
        std::cout << ANSI_COLOR_RESET;

        std::string configFilePath = bcr.install_dir + "/" + "config";
        std::string configCmd = "csms_config -T " + configFilePath + " ";
        std::string cmd;
        genConfigUpdateCommand(cmd);
        configCmd += cmd;

        rc = commonExe(sso, configCmd, buff, sizeof buff);
        std::cout << ANSI_COLOR_GREEN;
        std::cout << buff << std::endl;
        std::cout << ANSI_COLOR_RESET;
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
    }
    return 0;
}

int ECSManager::writeSysData(const char* sn, int cpuNum, const char* cpuModels)
{   
    std::string file = "output/" + kSysdataFile;
    FILE* f = fopen(file.c_str(), "w");
    if (NULL == f) {
        return -1;
    }
    fprintf(f, "%s\n%d\n%s\n", sn, cpuNum, cpuModels);
    fclose(f);
    return 0;
}   

int ECSManager::updateEXE(std::string& sql, std::string& updateFile)
{
    std::vector<SSHOpreationCmd> opCmds;
    SSHOpreationCmd cmd;
    std::string remoteFilePath;
    char _buf[512] = {'\0'};

    if (updateFile.size() != 0) {
        m_updatefile_path = updateFile;
        StringUtils::GetFileNameByPath(m_updatefile_path, &m_updatefile_name);
    }

    if (!FsUtils::isFileExist(m_updatefile_path.c_str())) {
        std::cout << m_updatefile_path << " is not exist !" << std::endl;
        return -1;
    }

    printf("Do you want to update [%s] (Y/N): ", m_updatefile_path.c_str());
    while (fgets(_buf, sizeof(_buf), stdin)) {
        if (_buf[0] == 'Y' || _buf[0] == 'y') {
            remoteFilePath = kUpdateRemoteDir + "/" + m_updatefile_name;
            cmd.cmd = m_updatefile_path + ":" + remoteFilePath;
            //std::cout << cmd.cmd << std::endl;
            cmd.type = kSSHSendfile;
            opCmds.push_back(cmd);

            cmd.cmd = remoteFilePath + " -u";
            //std::cout << cmd.cmd << std::endl;
            cmd.type = kSSHExeCmd;
            opCmds.push_back(cmd);
/*            
            cmd.cmd = "rm -f " + remoteFilePath;
            //std::cout << cmd.cmd << std::endl;
            cmd.type = kSSHExeCmd;
            opCmds.push_back(cmd);
*/
            fillOpQueueBySQLCmds(sql.c_str(), opCmds);
            runQ();
            break;
        } else {
            return 1;
        }
    }
    return 0;
}

int ECSManager::formatPCIaddr(std::string& addr_i, std::string* addr_o)
{
    char* p = new char[2048];
    char* q;
    int i = 0;
    snprintf(p, 2048, "%s", addr_i.c_str());
    q = p;
    while (*q) {
        if (*q == '\n' || *q == '\r' || *q == '\t') {
            *q = 0x20;
            i++;
        }
        q++;
    }
    addr_o->assign(p);
    delete[] p;
    return i;
}

int ECSManager::uninstallEXE(std::string& sql)
{
    char _buf[512] = {'\0'};
    char buff[4096];
    int rc = 0;

    printf("Do you want to uninstall csms(Y/N): ");
    while (fgets(_buf, sizeof(_buf), stdin)) {
        if (_buf[0] == 'Y' || _buf[0] == 'y') {
            SQLite::Statement query(m_db, sql);
            EcsTblRow euRow(&m_db);
            EcsBasicConfigTblRow bcr(&m_db);
            while (query.executeStep()) {
                euRow.getRow(query);
                bcr.getRow(euRow.house_id, euRow.ecs_id);
                if (bcr.id <= 0) {
                    std::cout << ANSI_COLOR_RED;
                    std::cout << "not data in config table" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
                    std::cout << ANSI_COLOR_RESET;
                    continue;
                }

                SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
                sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);

                std::string _cmdUnInstall = kRmCSMS;
                if (bcr.install_dir.size() > 3) {
                    _cmdUnInstall += " && rm -rf " + bcr.install_dir;
                }
                rc = commonExe(sso, _cmdUnInstall, buff, sizeof buff);
                if (rc != 0) {
                    std::cout << ANSI_COLOR_RED;
                    std::cout << buff << std::endl;
                    std::cout << ANSI_COLOR_RESET;
                    continue;
                }
                std::cout << ANSI_COLOR_GREEN;
                std::cout << "removed !" << std::endl;
                std::cout << ANSI_COLOR_RESET;
            }
            break;
        } else {
            return 1;
        }
    }
    return 0;
}

int ECSManager::routingInspection(std::string& sql)
{
    char _buf[512] = {'\0'};
    char buff[4096];
    int rc = 0;
    char output[40960] = {0};
    int n = 0;

    SQLite::Statement query(m_db, sql);
    EcsTblRow euRow(&m_db);
    EcsBasicConfigTblRow bcr(&m_db);
    while (query.executeStep()) {
        euRow.getRow(query);
        bcr.getRow(euRow.house_id, euRow.ecs_id);
        if (bcr.id <= 0) {
            std::cout << ANSI_COLOR_RED;
            std::cout << "not data in config table" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }

        SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
        sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);

        std::string routingInspection_cmd = "cpaccess -c check_state";
        rc = commonExe(sso, routingInspection_cmd, buff, sizeof buff);
        if (rc != 0) {
            std::cout << ANSI_COLOR_RED;
            n = snprintf(output, sizeof output, "### \nFail to get , %s, house_id:%d, ecs_id:%d \n", buff, euRow.house_id, euRow.ecs_id);
            snprintf(output + n, sizeof output, "### \n\n");
            std::cout << output << std::endl;
            std::cout << ANSI_COLOR_RESET;
            continue;
        }
//192.168.20.22|91014|DPI002|U1.6.13|24|0.03|1834|1962.22|1901.87|62.65|21.82|0|
//  2017-07-21 16:52:48|2020-07-20 16:52:48|2017-07-21 16:03:11|2017-07-28 11:09:03|0 D 0 H 0 M 32 S
//本机IP|机房号|设备号|版本号|CPU个数|CPU利用率|CPU频率|磁盘总量|磁盘可使用量|内存总量|内存可使用量|
//  license开始时间|license失效时间|系统运行时长|CQMS 系统运行时长|CQMS 运行时长
        std::vector<std::string> v;
        StringUtils::Split(buff, '|', v);
        if (v.size() >= 16) {
            n =  snprintf(output, sizeof output, "###, house_id:%d, ecs_id:%d\n\n", euRow.house_id, euRow.ecs_id);
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "名称            ",  "值", "阈值配置", "告警/提示");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "本机IP          ",  v[0].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "机房号          ",  v[1].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "设备号          ",  v[2].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "版本号          ",  v[3].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "CPU个数         ",  v[4].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "CPU利用率       ",  v[5].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "CPU频率         ",  v[6].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "磁盘总量        ",  v[7].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "磁盘可使用量    ",  v[8].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "内存总量        ",  v[9].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "内存可使用量    ",  v[10].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "阻断报文数      ",  v[11].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "license开始时间 ",  v[12].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "license失效时间 ",  v[13].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "系统运行时长    ",  v[14].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "CQMS系统运行时长",  v[15].c_str(), "", "");
            n += snprintf(output + n, sizeof(output) - n, "%-16s %-24s %-16s %-8s\n", "CQMS 运行时长   ",  v[16].c_str(), "", "");
            snprintf(output + n, sizeof output, "###\n");
        } else {
            n = snprintf(output, sizeof output, "###\n Fail to get, house_id:%d, ecs_id:%d \n", euRow.house_id, euRow.ecs_id);
            snprintf(output + n, sizeof output, "### \n\n");
        }
        std::cout << ANSI_COLOR_GREEN;
        std::cout << output << std::endl;
        std::cout << ANSI_COLOR_RESET;
    }
    return 0;
}

int ECSManager::installEXE(std::string& sql, std::string& installFile)
{
    char _buf[512] = {'\0'};
    char buff[4096];
    char cmd[4096];
    int rc = 0;

    if (installFile.size() != 0) {
        m_updatefile_path = installFile;
        StringUtils::GetFileNameByPath(m_updatefile_path, &m_updatefile_name);
    }
    if (!FsUtils::isFileExist(m_updatefile_path.c_str())) {
        std::cout << m_updatefile_path << " is not exist !" << std::endl;
        return -1;
    }
    std::string remoteFilePath = kUpdateRemoteDir + "/" + m_updatefile_name;

    printf("Do you want to install [%s] (Y/N): ", m_updatefile_path.c_str());
    while (fgets(_buf, sizeof(_buf), stdin)) {
        if (_buf[0] == 'Y' || _buf[0] == 'y') {
            SQLite::Statement query(m_db, sql);
            EcsTblRow euRow(&m_db);
            EcsBasicConfigTblRow bcr(&m_db);
            EcsMachineInfoTblRow mir(&m_db);
            while (query.executeStep()) {
                euRow.getRow(query);
                SSHOpreation sso(euRow.wan_ip, euRow.wan_port, euRow.user_wan, euRow.passwd_wan, !euRow.is_public);
                sso.ssh_tool_cmd_ = new SshToolCmd(euRow.lan_ip, euRow.lan_port, euRow.user_lan, euRow.passwd_lan);

                std::cout << ANSI_COLOR_GREEN;
                std::cout << "install csms on," << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
                std::cout << ANSI_COLOR_RESET;

                rc = commonUpload(sso, m_updatefile_path.c_str(), remoteFilePath.c_str());
                if (rc != 0) {
                    std::cout << "error to upload, " << m_updatefile_path << std::endl;
                    continue;
                }
                bcr.getRow(euRow.house_id, euRow.ecs_id);
                mir.getRow(euRow.house_id, euRow.ecs_id);

                if (bcr.id <= 0 || mir.id <= 0) {
                    std::cout << ANSI_COLOR_RED;
                    std::cout << "not data" << " house_id:" << euRow.house_id << " ecs_id:" << euRow.ecs_id << std::endl;
                    std::cout << ANSI_COLOR_RESET;
                    continue;
                }

                std::string pci_addr;
                formatPCIaddr(mir.eth_pci_addr, &pci_addr);
                snprintf(cmd, sizeof cmd, "%s -i %s -p %d -b '%s'", 
                                            remoteFilePath.c_str(),
                                            bcr.install_dir.c_str(),
                                            bcr.huge_page,
                                            pci_addr.c_str());
                std::string _cmdInstall = cmd;

                rc = commonExe(sso, _cmdInstall, buff, sizeof buff);
                std::cout << buff << std::endl;
                if (rc != 0) {
                    continue;
                }
                std::string _cmdConfig;
                snprintf(cmd, sizeof cmd, 
                        "csms_config -T %s/config "
                        " --kv eu.conf:euconf.idcid=%s "
                        " --kv eu.conf:euconf.localIp=%s "
                        " --kv eu.conf:euconf.houseNo=%d "
                        " --kv eu.conf:euconf.deviceNo=%s "
                        " --kv eu.conf:euconf.uploadType=%s ",
                        bcr.install_dir.c_str(),
                        bcr.idc_id.c_str(),
                        euRow.lan_ip.c_str(),
                        euRow.house_id,
                        bcr.ecs_id_str.c_str(),
                        bcr.upload_Type.c_str()
                       );
                _cmdConfig.append(cmd);
                _cmdConfig.append(" && ");

                snprintf(cmd, sizeof cmd, 
                        "csms_config -T %s/config "
                        " --kv config.txt:sendDeviceName=%s "
                        " --kv config.txt:dstMac=%s ",
                        bcr.install_dir.c_str(),
                        bcr.rst_interface.c_str(),
                        bcr.rst_dst_mac.c_str()
                       );
                _cmdConfig.append(cmd);

                rc = commonExe(sso, _cmdConfig, buff, sizeof buff);
                if (rc != 0) {
                    std::cout << buff << std::endl;
                    continue;
                }
/*                
                std::string _cmdRMInstallFile = "rm -f " + remoteFilePath;
                rc = commonExe(sso, _cmdRMInstallFile, buff, sizeof buff);
                std::cout << buff << std::endl;
                if (rc != 0) {
                    continue;
                }
*/
            }
            break;
        } else {
            return 1;
        }
    }
    return 0;
}

std::string ECSManager::licenseStartTime()
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep);
    char sTime[128] = {0};
    snprintf(sTime, 128, "%4d/%d/%d %02d:%02d:%02d", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
    return std::string(sTime);
}

int ECSManager::localEncodeCmd(const char validTime)
{
   char buf[BUF_SIZE]  = {'\0'}; 
   snprintf(buf, sizeof(buf), "./licensed -%c ", validTime);
   std::cout << "runnng:" << buf << std::endl;
   return system(buf);
}

void ECSManager::readLicenseTime(char *startTime, char *endTime, char validFlag)
{ 
    FILE *fp;
    char  buf[BUF_SIZE] = {'\0'};   

    fp = fopen("./output/licensed.conf", "r");
    if (!fp) 
    {
        printf("open licensed.conf  failed, errno:%d:%s\n", errno, strerror(errno));
        return ;
    }
    while (fgets(buf, BUF_SIZE - 1, fp) != NULL)
    {
        if (strstr(buf, "starttime="))
        {
            int datalen = strlen(buf) - strlen("starttime=") - 1 ;
            if ((datalen < BUF_SIZE - 1) && datalen > 0)
                strncpy(startTime, strlen("starttime=") + buf, datalen);
            break;
        }
    }
    fclose(fp);

    int year, month, date, hour, min, sec;
    sscanf(startTime, "%4d/%d/%d %02d:%02d:%02d", &year, &month, &date, &hour, &min, &sec);

    int validTime = 0;
    switch (validFlag)
    {
        case 't':
            validTime = 3*30*24*60*60;
            break;

        case 'o':
            validTime = 365*24*60*60;
            break;

        case 'f':
            validTime = 3*365*24*60*60 ;
            break;

        default:
            printf("not support validFlag:%c\n", validFlag);
            break;
    }

    struct tm info;
    info.tm_year = year - 1900;
    info.tm_mon = month  - 1;
    info.tm_mday = date;
    info.tm_hour = hour;
    info.tm_min =  min;
    info.tm_sec =  sec;
    info.tm_isdst = -1; 

    time_t  ret = mktime(&info);
    if ( ret == -1 )
    {   
        printf("format error\n");
        return  ; 
    }   

    time_t timep = ret + validTime;
    struct tm *p; 
    p = localtime(&timep);
    sprintf(endTime, "%4d/%d/%d %02d:%02d:%02d", (1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
}

void ECSManager::readLicenseData(char *boardSN, char *cpuNum, char *cpuModel)
{
    char line[BUF_SIZE] = {'\0'};   
    FILE* fd;

    if (!(fd = fopen("./output/system_data", "r")))
    {
        printf("open system_data  failed,errno:%d:%s\n", errno, strerror(errno));
        return  ;
    }

    int count =  0;
    while (fgets(line, sizeof(line), fd) != NULL)
    {
        count++;

        if (count == 1)   
        {
            strncpy(boardSN, line, strlen(line));
            memset(line,'\0' , sizeof(line));
            continue;
        }
        else if (count == 2)  
        {
            strncpy(cpuNum, line, strlen(line));
            memset(line,'\0' , sizeof(line));
            continue;
        } 

        char tmp[256]  = {'\0'};
        snprintf(tmp, sizeof(tmp), "%s;", line);

        strncpy(cpuModel, tmp, strlen(tmp));
        cpuModel = cpuModel + strlen(tmp) ;

        memset(line,'\0' , sizeof(line));
    }

    pclose(fd);
}



} //end of namespace
