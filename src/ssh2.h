//
//  Created by zhangm on 2017/3
//
#ifndef _ECSM_SSH2_H_
#define _ECSM_SSH2_H_
#include <arpa/inet.h>
#include <stdio.h>
#include <string>
#include <queue>
#include <pthread.h>
#include "libssh2.h"

namespace ecsm {

class SshSessionTuple
{
public:
    SshSessionTuple(std::string host, int port, std::string user, std::string passwd) 
        :m_host(host), m_port(port), m_user(user), m_passwd(passwd)
    {
        
    };
    ~SshSessionTuple() {
    };

    std::string genKey()
    {
        char port_str[16];
        std::string key;
        snprintf(port_str, sizeof port_str, "%d", m_port);
        key.assign(m_host + port_str);
        return key;
    }
public:
    std::string m_host;
    int m_port;
    std::string m_user;
    std::string m_passwd;
};

class SshChannel
{
public:
    enum Type {
        kChannelUnknow,
        kChannelExeCommand,
        kChannelShell,
        kChannelScpSend,
        kChannelScpReceive,
    };
public:
    SshChannel(LIBSSH2_CHANNEL* channel);
    SshChannel(LIBSSH2_SESSION* session);
    SshChannel(LIBSSH2_SESSION* session, SshChannel::Type type);
    ~SshChannel();
    int read(char* buffer, int buffer_len);
    int readStderr(char* buffer, int buffer_len);
    int write(const char* buffer, int buffer_len);
    int poll(int ms);
    void setEnv(const char* name, const char* value) {
        libssh2_channel_setenv(m_channel, name, value);
    }
    void setBlocking(int blocking) {
        libssh2_channel_set_blocking(m_channel, blocking);
    }
    void setType(Type type) {
        m_type = type;
    }
    Type getType() {
        return m_type;
    }
    int finish();
    void free();
    int exe(const char* command);
private:
    LIBSSH2_CHANNEL* m_channel;
    Type m_type;
};

class SshChannelScp : public SshChannel
{
public:
    static const int kSEND = 0;
    static const int kRECEIVE = 1;
public:
    SshChannelScp(LIBSSH2_CHANNEL* channel, std::string& scppath, std::string& local_path, int sr)
        : SshChannel(channel) {
        if (sr == kRECEIVE) {
            setType(SshChannel::kChannelScpReceive);
        } else {
            setType(SshChannel::kChannelScpSend);
        }
        m_rpath = scppath;
        m_lpath = local_path;
    }
    int transfer();
public:
    struct stat m_fileinfo;
private:
    std::string m_rpath;
    std::string m_lpath;
};

class SshSession
{
public:
    SshSession(const char* host, uint16_t port, long timeout);
    ~SshSession();
    int connect();
    int auth(const char* user, const char* passwd);
    int auth2(const char* user, const char* passwd);
    int waitSocket(int ms);
    SshChannel* startChannelCmd(const char* command);
    SshChannel* startChannelShell();
    SshChannelScp* startChannelScpGet(std::string& scppath, std::string& local_path);
    SshChannelScp* startChannelScpPost(std::string& local_path, std::string& scppath, int mode = 0777);
    int exeCommand(std::string& cmd);
    int exeCommand(const char* cmd);
    int exeCommandWithStdout(const char* cmd, char* stdout_str, int len);
    int sendFile(std::string& send_from, std::string& send_to);
    int receiveFile(std::string& rec_from, std::string& rec_to);
    int sendFile(std::string& cmd);
    int receiveFile(std::string& cmd);
    void lastError();
private:
    LIBSSH2_SESSION* m_session;
    std::string m_host;
    uint16_t m_port;
    int m_sock;
    pthread_mutex_t m_lock;
};

class LibSsh2 {
public:
    static const long kSSHDeaultTimeOut = 1000*6;
public:
    static void init();
    static void exit();
    static const char* version();
    static SshSession* newSeesion(std::string& host, int port, std::string& u, std::string& p, long timeout = kSSHDeaultTimeOut);
    static SshSession* newSeesion(SshSessionTuple& sTuple, long timeout = kSSHDeaultTimeOut);
};


struct SshToolCommand
{
    std::string cmd;
    SshChannel::Type channal_type;
};

class SshCmdQueue
{
public:
     SshCmdQueue() {
     }
     ~SshCmdQueue() {
        this->clear();
    };
    int runAll(SshSession* ssh_session) {
        int rc = 0;
        while (m_cmd_queue.size() > 0) {
            SshToolCommand* stc = m_cmd_queue.front();
            switch (stc->channal_type) {
                case SshChannel::kChannelExeCommand:
                    rc = ssh_session->exeCommand(stc->cmd);
                    break;
                case SshChannel::kChannelScpSend:
                    rc = ssh_session->sendFile(stc->cmd);
                    break;
                case SshChannel::kChannelScpReceive:
                    rc = ssh_session->receiveFile(stc->cmd);
                    break;
                default:
                    break;
            }
            if (rc != 0) {
                std::cout << "error, type=" << stc->channal_type << ", rc=" << rc << std::endl;
                ssh_session->lastError();
                this->clear();
                break;
            }
            m_cmd_queue.pop();
            delete stc;
        }
        return rc;
    }

    int add(std::string& cmd, SshChannel::Type type) {
        SshToolCommand* stc = new SshToolCommand;
        stc->cmd = cmd;
        stc->channal_type = type;
        m_cmd_queue.push(stc);
        return 0;
    }

    void clear() {
        while (m_cmd_queue.size() != 0) {
            SshToolCommand* stc = m_cmd_queue.front();
            delete stc;
            m_cmd_queue.pop();
        }
    }

private:
    std::queue<SshToolCommand*> m_cmd_queue;
};


}

#endif
