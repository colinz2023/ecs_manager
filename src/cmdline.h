#ifndef _ECSM_CMD_LINE_H
#define _ECSM_CMD_LINE_H
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <string.h>
#include <string>
#include <vector>
#include <set>


namespace ecsm {
/*class HintCompare 
{
public:
    bool operator() (const string &a, const string &b) const {
        //int n = b.size() > a.size() ? a.size() : b.size();
        int n = a.size();
        printf("\n%s\n", a.c_str());
        if (strncmp(a.c_str(), b.c_str(), n) < 0) {
            return true;
        } else {
            return false;
        }
    }
};*/

class CmdLine
{
public:
    CmdLine();
    CmdLine(const char *prompt_cstr, const char* history_file);
    ~CmdLine();
    void init();
    std::string readLine();
    void Left(int n);
    void Space(int n);
    void backSpace(int n);
    void clearLine();
    void writeLine(std::string& buf);
    void writeLine(const char* buf);
    void writeCmd();
    void toNline(int n);
    void addHints(std::string& hint);
    void addHints(std::vector<std::string>& v);
    int  compareHints(std::string* possible, std::string* append_str);
    void setPrompt(std::string& prompt);
private:
    struct termios* old_tty_atrr;

    void readHistory();
    void writeBackHistory();

    std::string m_historyFile;

    std::vector<std::string> history; 
    std::vector<std::string>::iterator curr;
    //set<string, HintCompare> hints;
    std::vector<std::string> hints;
    std::string prompt;
    std::string cmd;
    std::string cmd_buffer;
    int m_index;
    char c;
    int in_fd;
    int out_fd;
    int last_key;
};

} //end namespace

#endif
