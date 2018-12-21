#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "SQLiteCpp.h"
#include "ssh2.h"
#include "cmdline.h"
#include "gflags/gflags.h"

#include "ecs_manager.h"

using namespace ecsm;
//using namespace std;

int ipAdd(std::string& start_ip, int n, std::string* ip)
{
    int a, b, c, d;
    char p[128];
    sscanf(start_ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    snprintf(p, sizeof(p), "%d.%d.%d.%d", a, b, c, d + n);
    ip->assign(p);
    return 0;
}

int sshToolCmdString(std::string& host, 
                    int port, 
                    std::string& user,
                    std::string& passwd,
                    const char* pre_cmd,
                    std::string& cmd)
{
    char cmd_buff[1024];
    snprintf(cmd_buff, sizeof(cmd_buff),
        "/tmp/ssh_tool --host=%s --port=%d --user=%s --passwd=%s --pre_cmd=%s",
        host.c_str(),
        port,
        user.c_str(),
        passwd.c_str(),
        pre_cmd);
        cmd.assign(cmd_buff);
        return 0;
}

void signal_init()
{
    struct sigaction act;
    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGQUIT);
    sigaddset(&act.sa_mask, SIGTERM);
    sigaddset(&act.sa_mask, SIGINT);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);
    sigaction(SIGQUIT, &act, 0);
    sigaction(SIGTERM, &act, 0);
}

int cli(int argc, char *argv[])
{
    //test(argc, argv);
    signal_init();
    CmdLine cmdline("ECS_Manager_CLI> ");

    cmdline.addHints("update");
    cmdline.addHints("show");
    cmdline.addHints("test");
    cmdline.addHints("quit");

    while (1) {
        std::string cmd;
        cmd = cmdline.readLine();
        if (cmd.size() > 0) {
            if (cmd == "quit") {
                break;
            } else if (cmd == "test") {
                //cmdline.print("hello\n");
                //test(argc, argv);
            } else if (cmd == "test2") {
                //cmdline.print("hello\n");
                //test(argc, argv);
            } else if (cmd == "test3") {
                //cmdline.print("hello\n");
                //test(argc, argv);
            } else {
                cmdline.print(cmd.c_str());
            } 
        }
    }
    return 0;
}



DEFINE_string(update, "all", "");
DEFINE_string(update_file, "", "");
//DEFINE_int32(cli, 9, "");
DEFINE_bool(cli, false, "cli mode");
 
int main(int argc, char *argv[])
{
    gflags::SetVersionString("1.0.0.0");
    //gflags::SetUsageMessage("Usage: ");
    gflags::ParseCommandLineFlags(&argc, &argv, true);

    ECSManager ecs_manager;

    ecs_manager.updateECS(91014);

    if (FLAGS_cli) {
        return cli(argc, argv);
    }

    if (FLAGS_update.size() > 0) {
        
    }

    if (FLAGS_update == "all") {
        
    }


    gflags::ShutDownCommandLineFlags();

}




