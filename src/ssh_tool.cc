//
//  Created by zhangm on 2017/3
//

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <iostream>
#include <queue>
#include <string>
#include "ssh2.h"

using namespace ecsm;

const std::string SSH_TOOL_USAGE = "ssh_tool 参数\n"
"\t--port/-P, ssh port\n"
"\t--host/-H, host name\n"
"\t--user/-u, host name\n"
"\t--passwd/-p, \n"
"\t--cmd, 命令\n"
"\t--scp_s, 发送\n"
"\t--scp_r, 接收\n"
"example: \n"
"./ssh_tool -H 192.168.11.204 -pi 123456 --cmd='hostname' --scp_s='./ssh_tool:/tmp/ssh_tool' --cmd='md5sum /tmp/ssh_tool'";

static int FLAGS_port = 22;
static std::string FLAGS_host = "";
static std::string FLAGS_p = "";
static std::string FLAGS_u = "root";
static std::string FLAGS_cmd = "";
static std::string FLAGS_scp_s = "";
static std::string FLAGS_scp_r = "";

//class SshCmdQueue;

int main(int argc, char** argv)
{
    int rc = 0;
    int real_pass = 0;
    LibSsh2::init();
    SshCmdQueue cmdQueue;

    while (1) {
        int option_index = 0;
        int c;
        static struct option long_options[] = {
            {"port",      required_argument, 0, 'P'},
            {"host",      required_argument, 0, 'H'},
            {"passwd",    required_argument, 0, 'p'},
            {"user",      required_argument, 0, 'u'},
            {"cmd",       required_argument, 0,  1 },
            {"scp_s",     required_argument, 0,  2 },
            {"scp_r",     required_argument, 0,  3 },
            {"help",      no_argument,       0, 'h'},
            {0, 0,  0,  0 }
        };
        c = getopt_long(argc, argv, "P:H:p:u:hi",long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 'P':
                FLAGS_port = atoi(optarg);
                break;
            case 'H':
                FLAGS_host.assign(optarg);
                break;
            case 'p':
                FLAGS_p.assign(optarg);
                {
                    int i;
                    for (i = 0; optarg[i] != '\0'; ++i) {
                        optarg[i] = '0';
                    }
                }
                break;
            case 'u':
                FLAGS_u.assign(optarg);
                break;            
            case  1:
                FLAGS_cmd.assign(optarg);
                cmdQueue.add(FLAGS_cmd, SshChannel::kChannelExeCommand);
                break;            
            case  2:
                FLAGS_scp_s.assign(optarg);
                cmdQueue.add(FLAGS_scp_s, SshChannel::kChannelScpSend);
                break;           
            case  3:
                FLAGS_scp_r.assign(optarg);
                cmdQueue.add(FLAGS_scp_r, SshChannel::kChannelScpReceive);
                break;
            case 'i':
                real_pass = 1;
                break;
            case 'h':
                std::cout << SSH_TOOL_USAGE << std::endl;
                return 0;
                break;          
        }
    }

    SshSession* ssh_session = NULL;
    do {
        if (0 == FLAGS_host.length()) {
            std::cerr << "ssh_tool Error, host is NULL" << std::endl;
            std::cerr << "get help, please use --help" << std::endl;
            rc = 1;
            break;
        }
        ssh_session = new SshSession(FLAGS_host.c_str(), static_cast<uint16_t>(FLAGS_port), 1000*10);
        rc = ssh_session->connect();
        if (rc < 0) {
            std::cerr << "ssh_tool Error, connection error" << std::endl;
            break;
        }

        if (real_pass) {
            rc = ssh_session->auth2(FLAGS_u.c_str(), FLAGS_p.c_str());
        } else {
            rc = ssh_session->auth(FLAGS_u.c_str(), FLAGS_p.c_str());
        }
        if (rc < 0) {
            std::cerr << "ssh_tool Error, authentication error" << std::endl;
            break;
        }

        rc = cmdQueue.runAll(ssh_session);

        delete ssh_session;
    }
    while(0);
    LibSsh2::exit();

    if (rc != 0) {
        return -1;
    }
    return rc;
}
