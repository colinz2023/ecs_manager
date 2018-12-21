#ifndef _ECSM_UTILS_H_
#define _ECSM_UTILS_H_

#include <unistd.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ecsm {
class FsUtils
{
public:
    static int isFileExist(const char* path);
    static int mkDir(const char* dir);
    static bool DirectoryExists(const std::string &directory_path);
    static bool EnsureDirectory(const std::string &directory_path);
    static bool RemoveAllFiles(const std::string &directory_path);
};

class StringUtils 
{
public:
    static std::string& LTrim(std::string& s); 
    static std::string& RTrim(std::string& s);
    static std::string& Trim(std::string& s);
    static char* cstringTrim(char* str, int len);
    static int GetFileNameByPath(std::string& s, std::string* file_name);
    static int splitByDelimiter(std::string& str, std::string& first, std::string& second, char delimiter);
    static std::string itos(int i);
    static std::vector<std::string>& Split(const std::string &s, char delim, std::vector<std::string> &elems);
};

class IfUtils
{
public:
    static uint32_t ipAddrInt(std::string& ip);
    
};

namespace md5 {
std::string Md5(std::string dat);
std::string Md5(const void* dat, size_t len);
std::string Md5File(const char* filename);
std::string Md5File(FILE* file);
std::string Md5Sum6(std::string dat);
std::string Md5Sum6(const void* dat, size_t len);
} // ending namespace md5


namespace base64 {
bool Encode(const std::string& src, std::string* dst);
bool Decode(const std::string& src, std::string* dst);
char Base2Chr(unsigned char n);
// 求得某个字符在Base64编码表中的序号
unsigned char Chr2Base(char c);
int Base64EncodeLen(int n);
int Base64DecodeLen(int n);
} // end of namespace base64

int decrypto(std::string thiz_en, std::string* out_str);
int encrypto(char* buffer, int max_size, std::string* out_str);

} //end of namespace ecsm

#endif
