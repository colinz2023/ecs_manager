//
//  Created by zhangm on 2017/3
//
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <iostream>
#include <fstream>
#include <string>
#include "utils.h"
#include "ssh2.h"

namespace ecsm {

void LibSsh2::init()
{
    libssh2_init(0);
}

void LibSsh2::exit() 
{
    libssh2_exit();
}

const char* LibSsh2::version() {
    return libssh2_version(0);
}

SshSession* LibSsh2::newSeesion(std::string& host, int port, std::string& u, std::string& p, long timeout)
{
    int rc;
    SshSession* ssh_session = new SshSession(host.c_str(), static_cast<uint16_t>(port), timeout);
    rc = ssh_session->connect();
    if (rc < 0) {
        std::cerr << "LibSsh2 Error, connection error" << std::endl;
        delete ssh_session;
        return NULL;
    }
    rc = ssh_session->auth(u.c_str(), p.c_str());
    if (rc < 0) {
        std::cerr << "LibSsh2 Error, authentication error" << std::endl;
        delete ssh_session;
        return NULL;
    }
    return ssh_session;
}

SshSession* LibSsh2::newSeesion(SshSessionTuple& sTuple, long timeout)
{
    int rc;
    SshSession* ssh_session = new SshSession(sTuple.m_host.c_str(), static_cast<uint16_t>(sTuple.m_port), timeout);
    rc = ssh_session->connect();
    if (rc < 0) {
        std::cerr << "LibSsh2 Error, connection error" << std::endl;
        ssh_session->lastError();
        delete ssh_session;
        return NULL;
    }
    rc = ssh_session->auth(sTuple.m_user.c_str(), sTuple.m_passwd.c_str());
    if (rc < 0) {
        std::cerr << "LibSsh2 Error, authentication error" << std::endl;
        ssh_session->lastError();
        delete ssh_session;
        return NULL;
    }
    return ssh_session;
}

SshSession::SshSession(const char* host, uint16_t port, long timeout)
{
    m_session = libssh2_session_init();
    assert(m_session != NULL);
    libssh2_session_set_timeout(m_session, timeout);
    //pthread_mutex_init(&m_lock, NULL);
    m_host.assign(host);
    m_port = port;
    m_sock = -1;
}

SshSession::~SshSession()
{
    if (m_session) {
        libssh2_session_disconnect(m_session, "Bye");
        libssh2_session_free(m_session);
        ::close(m_sock);
        //pthread_mutex_destroy(&m_lock);
        //std::cout << "~SshSession" << std::endl;
    }
}

int SshSession::connect()
{
    int rc;
    struct addrinfo ai_hints, *result;
    m_sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (m_sock < 0) {
        std::cerr << "socket error," << strerror(errno) << std::endl;
        return -1;
    }
    
    memset(&ai_hints, 0, sizeof(struct addrinfo));
    ai_hints.ai_family   = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_STREAM;
    ai_hints.ai_protocol = IPPROTO_TCP;

    char port_str[32];
    snprintf(port_str, sizeof port_str, "%d", m_port);

    rc = getaddrinfo(m_host.c_str(), port_str, &ai_hints, &result);
    if (rc || !result) {
        ::close(m_sock);
        return -1;
    }

    rc = ::connect(m_sock, result->ai_addr, result->ai_addrlen);
    if (rc < 0) {
        ::close(m_sock);
        std::cerr << "connect error " << strerror(errno) << std::endl;
        return -1;
    }
    freeaddrinfo(result);

    if (rc < 0) {
        ::close(m_sock);
        return -1;
    }
    rc = libssh2_session_handshake(m_session, m_sock);
    if (0 != rc) {
        std::cerr << "Failure establishing SSH session: " << rc << std::endl;
    }
    return 0;
}

int SshSession::auth(const char* user, const char* passwd)
{
    std::string pe(passwd);
    std::string po;
    ecsm::decrypto(pe, &po);
    if (libssh2_userauth_password(m_session, user, po.c_str()) != 0) {
        lastError();
        return -1;
    }
    return 0;
}

int SshSession::auth2(const char* user, const char* passwd)
{
    if (libssh2_userauth_password(m_session, user, passwd) != 0) {
        lastError();
        return -1;
    }
    return 0;
}

int SshSession::waitSocket(int ms)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = ms / 1000;
    timeout.tv_usec = (ms % 1000) * 1000;

    FD_ZERO(&fd);
    FD_SET(m_sock, &fd);
    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(m_session);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = ::select(m_sock + 1, readfd, writefd, NULL, &timeout);
    return rc;
}

SshChannel* SshSession::startChannelCmd(const char* command)
{
    int rc = 0;
    SshChannel* ssh_channel = NULL;

    //pthread_mutex_lock(&m_lock);
    ssh_channel = new SshChannel(m_session, SshChannel::kChannelExeCommand);
    //pthread_mutex_unlock(&m_lock);
    ssh_channel->setBlocking(1);

    while ((rc = ssh_channel->exe(command)) == LIBSSH2_ERROR_EAGAIN) {
        //waitsocket(m_sock, m_session);
    }
    if (rc != 0) {
        delete ssh_channel;
        std::cerr << "ssh channel error " << std::endl;
        return NULL;
    }
    return ssh_channel;
}

SshChannel* SshSession::startChannelShell()
{
    SshChannel* ssh_channel = NULL;

    ssh_channel = new SshChannel(m_session, SshChannel::kChannelShell);
    ssh_channel->setBlocking(1);
    return ssh_channel;
}

SshChannelScp* SshSession::startChannelScpGet(std::string& scppath, std::string& local_path)
{
    LIBSSH2_CHANNEL* channel;
    SshChannelScp* ssh_channel = NULL;
    struct stat fileinfo;

    channel = libssh2_scp_recv(m_session, scppath.c_str(), &fileinfo);
    if (!channel) {
        std::cerr << "Unable to open a session: " << libssh2_session_last_errno(m_session) << std::endl;
        return NULL;
    }
    //pthread_mutex_lock(&m_lock);
    ssh_channel = new SshChannelScp(channel, scppath, local_path, SshChannelScp::kRECEIVE);
    //pthread_mutex_unlock(&m_lock);
    ssh_channel->setBlocking(1);
    ssh_channel->m_fileinfo = fileinfo;
    return ssh_channel;
}

SshChannelScp* SshSession::startChannelScpPost(std::string& local_path, std::string& scppath, int mode)
{
    LIBSSH2_CHANNEL* channel;
    SshChannelScp* ssh_channel = NULL;
    struct stat fileinfo;

    stat(local_path.c_str(), &fileinfo);
    channel = libssh2_scp_send(m_session, scppath.c_str(), mode, (unsigned long)fileinfo.st_size);
    if (!channel) {
        char *errmsg;
        int errlen;
        int err = libssh2_session_last_error(m_session, &errmsg, &errlen, 0);
        std::cerr << "Unable to open a session: " << err << " " << errmsg << std::endl;
        return NULL;
    }
    //pthread_mutex_lock(&m_lock);
    ssh_channel = new SshChannelScp(channel, scppath, local_path, SshChannelScp::kSEND);
    //pthread_mutex_unlock(&m_lock);
    ssh_channel->setBlocking(1);
    ssh_channel->m_fileinfo = fileinfo;
    return ssh_channel;
}

int SshSession::exeCommand(const char* cmd)
{
    char buffer[0x4000];
    int ret = 0;
    SshChannel* exe_channel = this->startChannelCmd(cmd);
    if (exe_channel == NULL) {
        std::cerr << "Error, ssh command channel start error" << std::endl;
        return -1;
    }
    do {
        memset(buffer, 0, sizeof(buffer));
        ret = exe_channel->read(buffer, sizeof(buffer));
        if (ret > 0)
            std::cout << buffer;
    } while (ret != 0 && ret != -1);

    ret = exe_channel->finish();
    delete exe_channel;
    return ret;
}

int SshSession::exeCommandWithStdout(const char* cmd, char* stdout_str, int len)
{
    int ret = 0;
    int rev_len;
    SshChannel* exe_channel = this->startChannelCmd(cmd);
    if (exe_channel == NULL) {
        std::cerr << "Error, ssh command channel start error" << std::endl;
        return -1;
    }
    rev_len = exe_channel->read(stdout_str, len);
    if (rev_len > 0 && rev_len < len) {
        stdout_str[rev_len] = 0;
    }
    ret = exe_channel->finish();
    delete exe_channel;
    return ret;
}

int SshSession::exeCommand(std::string& cmd)
{
    return exeCommand(cmd.c_str());
}

int SshSession::sendFile(std::string& send_from, std::string& send_to)
{
   int rc = 0;

   if (!FsUtils::isFileExist(send_from.c_str())) {
        std::cerr << "Error, " << send_from + " is not exist" << std::endl;
        return -1;
   }
   std::string md5sum = "test -e " + send_to + " && md5sum " + send_to;
   char remote_md5[256] = {0};
   std::string md5_str =  ecsm::md5::Md5File(send_from.c_str());
   memset(remote_md5, '\0', sizeof remote_md5);
   exeCommandWithStdout(md5sum.c_str(), remote_md5, 256);

   rc = strncmp(remote_md5, md5_str.c_str(), md5_str.size());
   if (rc == 0 && strlen(remote_md5) > 32) {
        return 0;
   }

   SshChannelScp* scp_channel = this->startChannelScpPost(send_from, send_to, 0777);
    if (scp_channel) {
        scp_channel->transfer();
        rc = scp_channel->finish();
        delete scp_channel;
    } else {
        lastError();
        rc = -1;
    }
    return rc;
}

int SshSession::sendFile(std::string& cmd)
{
    std::string::size_type n = cmd.find_first_of(":");
    if (n == std::string::npos) {
        return -1;
    }
    std::string send_from = cmd.substr(0, n);
    std::string send_to = cmd.substr(n + 1, cmd.size());
    return this->sendFile(send_from, send_to);
}

int SshSession::receiveFile(std::string& cmd)
{
    std::string::size_type n = cmd.find_first_of(":");
    if (n == std::string::npos) {
        return -1;
    }
    std::string rec_from = cmd.substr(0, n);
    std::string rec_to = cmd.substr(n + 1, cmd.size());
    return this->receiveFile(rec_from, rec_to);
}

int SshSession::receiveFile(std::string& rec_from, std::string& rec_to)
{
    int rc = 0;
    SshChannelScp* scp_channel = this->startChannelScpGet(rec_from, rec_to);
    if (scp_channel) {
        scp_channel->transfer();
        scp_channel->finish();
        delete scp_channel;
    } else {
        std::cerr << "Error, scp rec scp_channel start error" << std::endl;
        rc = -1;
    }
    return rc;
}

void SshSession::lastError()
{
    char *errmsg;
    int errlen;
    int err = libssh2_session_last_error(m_session, &errmsg, &errlen, 0);
    int err_no = libssh2_session_last_errno(m_session);
    if (err_no) {
        std::cerr << err << "," << errmsg << std::endl;
    }
}

SshChannel::SshChannel(LIBSSH2_CHANNEL* channel)
    : m_type(SshChannel::kChannelUnknow)
{
    m_channel = channel;
}

SshChannel::SshChannel(LIBSSH2_SESSION *session, SshChannel::Type type)
{
    LIBSSH2_CHANNEL* channel;
    while ((channel = libssh2_channel_open_session(session)) == NULL &&
                libssh2_session_last_error(session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) {
        //waitsocket(m_sock, m_session);
    }
	if (SshChannel::kChannelShell == type) {
		if (libssh2_channel_request_pty(channel, "shell")) {
			libssh2_channel_free(channel);
			throw "pty error";
		}
		/* Open a SHELL on that pty */
		if (libssh2_channel_shell(channel)) {
			libssh2_channel_free(channel);
			throw "shell error";
		}
	}
    m_channel = channel;
    m_type = type;
}

SshChannel::~SshChannel() 
{
    if (m_channel) {
        libssh2_channel_free(m_channel);
    }
}

int SshChannel::exe(const char* command)
{
    return libssh2_channel_exec(m_channel, command);
}

void SshChannel::free()
{
    if (m_channel != NULL) {
        libssh2_channel_free(m_channel);
    }
}

int SshChannel::finish()
{
    int  exitcode = 0;
    char *exitsignal=(char *)"OK";

    if (m_type == kChannelScpSend) {
        libssh2_channel_send_eof(m_channel);
        libssh2_channel_wait_eof(m_channel);
        return 0;
    } else if (m_type == kChannelScpReceive) {
        return 0;
    }

    while ((exitcode = libssh2_channel_close(m_channel)) == LIBSSH2_ERROR_EAGAIN) {
        libssh2_channel_wait_closed(m_channel);
        //waitsocket(sock, session);
    }

    if (exitcode == 0) {
        exitcode = libssh2_channel_get_exit_status(m_channel);
        libssh2_channel_get_exit_signal(m_channel, &exitsignal, NULL, NULL, NULL, NULL, NULL);
    } else {
        std::cerr << "finish close error:" << exitcode << std::endl;
        char buf[512] =  {0,};
        readStderr(buf, sizeof(buf));
        std::cerr << buf << std::endl;
        return -1;
    }

    if (exitcode != 0) {
        //std::cerr << m_type << ",finish exitcode:" << exitcode << std::endl;
        char buf[512] =  {0,};
        readStderr(buf, sizeof(buf));
        std::cerr << buf << std::endl;
    }
    return exitcode;
}

int SshChannel::read(char* buffer, int buffer_len)
{
    int rc;
    rc = libssh2_channel_read(m_channel, buffer, buffer_len);
    return rc;
}

int SshChannel::write(const char* buffer, int buffer_len)
{
    int rc;
    int len = buffer_len;
    //rc = libssh2_channel_write(m_channel, buffer, buffer_len);
    //rc = libssh2_channel_write_ex(m_channel, 0, buffer, buffer_len);
    do {
        /* write the same data over and over, until error or completion */ 
        rc = libssh2_channel_write(m_channel, buffer, len);
        if (rc < 0) {
            std::cerr << "SshChannel write ERROR:" << rc << std::endl;
            break;
        }
        else {
            buffer += rc;
            len -= rc;
        }
    } while (len);
    return rc;
}

int SshChannel::readStderr(char* buffer, int buffer_len)
{
    int rc;
    rc = libssh2_channel_read_stderr(m_channel, buffer, buffer_len);
    return rc;
}

int SshChannel::poll(int ms)
{
    LIBSSH2_POLLFD *fds = new LIBSSH2_POLLFD;
    fds->type = LIBSSH2_POLLFD_CHANNEL;
    fds->fd.channel = m_channel;
    fds->events = LIBSSH2_POLLFD_POLLIN;
    int rc = (libssh2_poll(fds, 1, ms));
    if (rc < 0)
        return -1;
    if (rc)
        return 1;
    // time out 
    return 0;
}

int SshChannelScp::transfer()
{
    int ret = 0;
    int buffer_len = m_fileinfo.st_size > 6400*1000 ? 6400*1000 : m_fileinfo.st_size;
    char* buffer = new char[buffer_len];

    if (kChannelScpReceive == getType()) {
        std::ofstream out(m_lpath.c_str(), std::ofstream::out|std::ofstream::binary); 
        int got = 0;
        while (got < m_fileinfo.st_size) {
            int amount =  buffer_len;
            if ((m_fileinfo.st_size - got) < amount) {
                amount = (int)(m_fileinfo.st_size - got);
            }
            memset(buffer, 0, buffer_len);
            ret = this->read(buffer, amount);
            if (ret >= 0) {
                out.write (buffer, ret);
            }
            //std::cout << buffer << "ret = " << ret << std::endl;
        #ifdef DEBUG
            std::cout << "got = " << got << std::endl;
        #endif
            got  += ret;
        }
        out.close();
    } else if (kChannelScpSend) {
        std::ifstream ins(m_lpath.c_str(), std::ifstream::binary);
        do {
            int got = 0;
            got = ins.readsome(buffer, buffer_len);
            if (got <= 0) {
                /* end of file */ 
                break;
            }
            ret = this->write(buffer, got);
        } while (1);
        ins.close();
    }
    delete[] buffer;
    return ret;
}

} //end namespace

