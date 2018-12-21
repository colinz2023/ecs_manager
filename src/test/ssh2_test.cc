#include "ssh2.h"
#include <iostream>
#include <fstream>  
#include <string>
using namespace ecsm;
int main(int argc, char const *argv[])
{
    int ret;
    char buffer[0x4000];

    LibSsh2::init();
    SshSession* ssh_session = new SshSession("192.168.11.204", 22);
    ssh_session->connect();
    ssh_session->auth("root", "123456");
    SshChannel* exe_channel = ssh_session->startChannelCmd("ls /opt");

/*    
    SshChannel* exe_channel;
    try {
        exe_channel = ssh_session->startChannelShell();
    } catch (std::string err) {
        std::cout << "xx";
    }
    std::string cmd_ls("ls\n");
    memset(buffer, 0, sizeof(buffer));
    ret = exe_channel->read(buffer, sizeof(buffer));
    std::cout << buffer;
    exe_channel->write(cmd_ls.c_str(), cmd_ls.size());
    memset(buffer, 0, sizeof(buffer));
    ret = exe_channel->read(buffer, sizeof(buffer));
    std::cout << buffer;
    memset(buffer, 0, sizeof(buffer));
    ret = exe_channel->read(buffer, sizeof(buffer));
    std::cout << buffer;
    memset(buffer, 0, sizeof(buffer));
    ret = exe_channel->read(buffer, sizeof(buffer));
    std::cout << buffer;
*/
    do {
        memset(buffer, 0, sizeof(buffer));
        ret = exe_channel->read(buffer, sizeof(buffer));
        if (ret > 0)
            std::cout << buffer;
    } while (ret != 0);
    int rc = exe_channel->finish();
    delete exe_channel;

    std::string file_path("/root/httpwap.cap");
    std::string local_path("./httpwap.cap");
    SshChannelScp* scp_channel = ssh_session->startChannelScpGet(file_path, local_path);
    if (scp_channel) {
        scp_channel->transfer();
        scp_channel->finish();
        delete scp_channel;
    }
    delete ssh_session;
    LibSsh2::exit();
    std::cout << std::endl << "end" << std::endl;
}
