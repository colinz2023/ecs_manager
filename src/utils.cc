#include "utils.h"
#include <rpc/des_crypt.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <sstream>

namespace ecsm {

bool FsUtils::DirectoryExists(const std::string &directory_path) 
{
    struct stat info;
    if (stat(directory_path.c_str(), &info) != 0) {
        return false;
    }

    if (info.st_mode & S_IFDIR) {
        return true;
    }
    return false;
}

bool FsUtils::EnsureDirectory(const std::string &directory_path)
{
    std::string path = directory_path;
    for (size_t i = 1; i < directory_path.size(); ++i) {
        if (directory_path[i] == '/') {
            path[i] = 0;
            if (mkdir(path.c_str(), S_IRWXU) != 0) {
                if (errno != EEXIST) {
                    return false;
                }
            }
            path[i] = '/';
        }
    }
    if (mkdir(path.c_str(), S_IRWXU) != 0) {
        if (errno != EEXIST) {
            return false;
        }
    }
    return true;
}

bool FsUtils::RemoveAllFiles(const std::string &directory_path) 
{
    DIR *directory = opendir(directory_path.c_str());
    struct dirent *file;
    while ((file = readdir(directory)) != NULL) {
        if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, "..")) {
            continue;
        }
        std::string file_path = directory_path + "/" + file->d_name;
        if (unlink(file_path.c_str()) < 0) {
            fprintf(stderr, "Fail to remove file, %s: err: %s \n", file_path.c_str(), strerror(errno));
            closedir(directory);
            return false;
        }
    }
    closedir(directory);
    return true;
}

int FsUtils::isFileExist(const char* path)
{
    if (access(path, F_OK) < 0) {
        return 0;
    }
    return 1;
}

int FsUtils::mkDir(const char* dir)
{
    const char* p = dir;
    int len = 0;
    char tmp[strlen(dir) + 1];
    int mode = 0777;
    while ((p = strchr(p, '/')) != NULL) {
        len = p - dir;
        if (len > 0) {
            memcpy(tmp, dir, len);
            tmp[len] = '\0';
            if ((mkdir(tmp, mode) < 0) && (errno != EEXIST)) {
                return -3;
            }
        }
        p += 1;
    }
    if ((mkdir(dir, mode) < 0) && (errno != EEXIST)) {
        return -2;
    }
    return 0;
}

int StringUtils::GetFileNameByPath(std::string& s, std::string* file_name)
{
    file_name->assign(s);
    file_name->erase(file_name->find_last_not_of(" \t\n\r\\/") + 1);
    file_name->erase(0, file_name->find_last_of("\\/") + 1);
    return 0;
}

int StringUtils::splitByDelimiter(std::string& str, std::string& first, std::string& second, char delimiter)
{
    std::string::size_type n;
    n = str.find(delimiter);
    if (std::string::npos == n) {
        first = "";
        second = "";
        return -1;
    }
    first = str.substr(0, n);
    second = str.substr(n + 1);
    return 0;
}

std::string& StringUtils::LTrim(std::string& s)
{
    return s.erase(0, s.find_first_not_of(" \t\n\r"));
}

std::string& StringUtils::RTrim(std::string& s)
{
    return s.erase(s.find_last_not_of(" \t\n\r") + 1);
}

std::string& StringUtils::Trim(std::string& s)
{
    return RTrim(LTrim(s));
}

std::string StringUtils::itos(int i)
{
    char buf[128];
    snprintf(buf, sizeof buf, "%d", i);
    return std::string(buf);
}

std::vector<std::string>&
StringUtils::Split(const std::string &s, char delim, std::vector<std::string> &elems)
{
    std::stringstream ss(s);
    std::string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

/*std::string& StringUtils::TrimLine(std::string& s)
{
    std::string b(s);
    
    return RTrim(LTrim(s));
}*/

char* StringUtils::cstringTrim(char* str, int len)
{
    char        *end;
    if (len == 0)
        return (str);

    end = (str + len) - 1;
    while (isspace(*(unsigned char *)str) && str < end)
        str++;

    while (isspace(*(unsigned char *)end) && end > str)
        *(end)-- = '\0';

    return (str);

}

uint32_t IfUtils::ipAddrInt(std::string& ip)
{
    uint32_t i = 0;
    inet_pton(AF_INET, ip.c_str(), &i);
    return i;
}

namespace md5 {
//baidu galaxy
#define F(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)   ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)   ((x) ^ (y) ^ (z))
#define I(x, y, z)   ((y) ^ ((x) | ~(z)))
#define STEP(f, a, b, c, d, x, t, s) \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
        (a) += (b);

#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
            (*(MD5_u32 *)&ptr[(n) * 4])
#define GET(n) \
            SET(n)
#else
#define SET(n) \
            (ctx->block[(n)] = \
            (MD5_u32)ptr[(n) * 4] | \
            ((MD5_u32)ptr[(n) * 4 + 1] << 8) | \
            ((MD5_u32)ptr[(n) * 4 + 2] << 16) | \
            ((MD5_u32)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
            (ctx->block[(n)])
#endif

typedef unsigned int MD5_u32;

typedef struct {
    MD5_u32 lo, hi;
    MD5_u32 a, b, c, d;
    unsigned char buffer[64];
    MD5_u32 block[16];
} MD5_CTX;

static void MD5_Init(MD5_CTX* ctx);
static void MD5_Update(MD5_CTX* ctx, const void* data, unsigned long size);
static void MD5_Final(unsigned char* result, MD5_CTX* ctx);

static const void* body(MD5_CTX* ctx, const void* data, unsigned long size) {
    const unsigned char* ptr;
    MD5_u32 a, b, c, d;
    MD5_u32 saved_a, saved_b, saved_c, saved_d;

    ptr = (const unsigned char*)data;
    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
        STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
        STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
        STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
        STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
        STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
        STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
        STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
        STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
        STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
        STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
        STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
        STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
        STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
        STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
        STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)
        STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
        STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
        STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
        STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
        STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
        STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
        STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
        STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
        STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
        STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
        STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
        STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
        STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
        STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
        STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
        STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)
        STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
        STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
        STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
        STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
        STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
        STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
        STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
        STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
        STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
        STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
        STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
        STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
        STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
        STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
        STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
        STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)
        STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
        STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
        STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
        STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
        STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
        STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
        STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
        STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
        STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
        STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
        STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
        STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
        STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
        STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
        STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
        STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (size -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;

    return ptr;
}

void MD5_Init(MD5_CTX* ctx) {
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;

    ctx->lo = 0;
    ctx->hi = 0;
}

void MD5_Update(MD5_CTX* ctx, const void* data, unsigned long size) {
    MD5_u32 saved_lo;
    unsigned long used, free;

    saved_lo = ctx->lo;

    if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo) {
        ctx->hi++;
    }

    ctx->hi += size >> 29;
    used = saved_lo & 0x3f;

    if (used) {
        free = 64 - used;

        if (size < free) {
            memcpy(&ctx->buffer[used], data, size);
            return;
        }

        memcpy(&ctx->buffer[used], data, free);
        data = (unsigned char*)data + free;
        size -= free;
        body(ctx, ctx->buffer, 64);
    }

    if (size >= 64) {
        data = body(ctx, data, size & ~(unsigned long)0x3f);
        size &= 0x3f;
    }

    memcpy(ctx->buffer, data, size);
}

void MD5_Final(unsigned char* result, MD5_CTX* ctx) {
    unsigned long used, free;
    used = ctx->lo & 0x3f;
    ctx->buffer[used++] = 0x80;
    free = 64 - used;

    if (free < 8) {
        memset(&ctx->buffer[used], 0, free);
        body(ctx, ctx->buffer, 64);
        used = 0;
        free = 64;
    }

    memset(&ctx->buffer[used], 0, free - 8);
    ctx->lo <<= 3;
    ctx->buffer[56] = ctx->lo;
    ctx->buffer[57] = ctx->lo >> 8;
    ctx->buffer[58] = ctx->lo >> 16;
    ctx->buffer[59] = ctx->lo >> 24;
    ctx->buffer[60] = ctx->hi;
    ctx->buffer[61] = ctx->hi >> 8;
    ctx->buffer[62] = ctx->hi >> 16;
    ctx->buffer[63] = ctx->hi >> 24;
    body(ctx, ctx->buffer, 64);
    result[0] = ctx->a;
    result[1] = ctx->a >> 8;
    result[2] = ctx->a >> 16;
    result[3] = ctx->a >> 24;
    result[4] = ctx->b;
    result[5] = ctx->b >> 8;
    result[6] = ctx->b >> 16;
    result[7] = ctx->b >> 24;
    result[8] = ctx->c;
    result[9] = ctx->c >> 8;
    result[10] = ctx->c >> 16;
    result[11] = ctx->c >> 24;
    result[12] = ctx->d;
    result[13] = ctx->d >> 8;
    result[14] = ctx->d >> 16;
    result[15] = ctx->d >> 24;
    memset(ctx, 0, sizeof(*ctx));
}

/**
 * Return Calculated raw result(always little-endian),
 * the size is always 16
 */
void Md5Bin(const void* dat, size_t len, unsigned char out[16]) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, dat, len);
    MD5_Final(out, &c);
}

static char hb2hex(unsigned char hb) {
    hb = hb & 0xF;
    return hb < 10 ? '0' + hb : hb - 10 + 'a';
}

std::string Md5File(const char* filename) {
    FILE* file = ::fopen(filename, "rb");
    std::string res = Md5File(file);
    ::fclose(file);
    return res;
}

std::string Md5File(FILE* file) {
    MD5_CTX c;
    MD5_Init(&c);

    char buff[BUFSIZ];
    unsigned char out[16];
    size_t len = 0;

    while ((len = ::fread(buff , sizeof(char), BUFSIZ, file)) > 0) {
        MD5_Update(&c, buff, len);
    }

    MD5_Final(out, &c);

    std::string res;

    for (size_t i = 0; i < 16; ++ i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }

    return res;
}

std::string Md5(const void* dat, size_t len) {
    std::string res;
    unsigned char out[16];
    Md5Bin(dat, len, out);

    for (size_t i = 0; i < 16; ++ i) {
        res.push_back(hb2hex(out[i] >> 4));
        res.push_back(hb2hex(out[i]));
    }

    return res;
}

std::string Md5(std::string dat) {
    return Md5(dat.c_str(), dat.length());
}

} //end of namespace md5


namespace base64 {
static char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/**
 * @Function: 根据在Base64编码表中的序号求得某个字符
 *            0-63 : A-Z(25) a-z(51), 0-9(61), +(62), /(63)
 * @Param:    unsigned char n
 * @Return:   字符
 */
char Base2Chr(unsigned char n)
{
    n &= 0x3F;
    if (n < 26)
        return static_cast<char>(n + 'A');
    else if (n < 52)
        return static_cast<char>(n - 26 + 'a');
    else if (n < 62)
        return static_cast<char>(n - 52 + '0');
    else if (n == 62)
        return '+';
    else
        return '/';
}

/**
 * @Function: 求得某个字符在Base64编码表中的序号
 * @Param:    char c   字符
 * @Return:   序号值
 */
unsigned char Chr2Base(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (unsigned char)(c - 'A');
    else if (c >= 'a' && c <= 'z')
        return (unsigned char )(c - 'a' + 26);
    else if (c >= '0' && c <= '9')
        return ( unsigned char )(c - '0' + 52);
    else if (c == '+')
        return 62;
    else if (c == '/')
        return 63;
    else
        return 64;  //  无效字符
}

bool Encode(const std::string& src, std::string* dst)
{
    if (0 == src.size() || NULL == dst)
    {
        return false;
    }

    dst->resize(Base64EncodeLen(src.size()));

    int c = -1;

    unsigned char* p = reinterpret_cast<unsigned char*>(&(*dst)[0]);
    unsigned char* s = p;
    unsigned char* q = reinterpret_cast<unsigned char*>(const_cast<char*>(&src[0]));

    for (size_t i = 0; i < src.size();)
    {
        // 处理的时候，都是把24bit当作一个单位，因为3*8=4*6
        c = q[i++];
        c *= 256;
        if (i < src.size())
            c += q[i];
        i++;
        c *= 256;
        if (i < src.size())
            c += q[i];
        i++;

        // 每次取6bit当作一个8bit的char放在p中
        p[0] = base64_code[(c & 0x00fc0000) >> 18];
        p[1] = base64_code[(c & 0x0003f000) >> 12];
        p[2] = base64_code[(c & 0x00000fc0) >> 6];
        p[3] = base64_code[(c & 0x0000003f) >> 0];

        // 这里是处理结尾情况
        if (i > src.size())
            p[3] = '=';

        if (i > src.size() + 1)
            p[2] = '=';

        p += 4; // 编码后的数据指针相应的移动
    }

    *p = 0;   // 防野指针
    dst->resize(p - s);

    return true;
}

bool Decode(const std::string& src, std::string* dst)
{
    if (0 == src.size() || NULL == dst)
    {
        return false;
    }

    dst->resize(Base64DecodeLen(src.size()));

    unsigned char* p = reinterpret_cast<unsigned char*>(&(*dst)[0]);
    unsigned char* q = p;
    unsigned char c = 0;
    unsigned char t = 0;

    for (size_t i = 0; i < src.size(); i++)
    {
        if (src[i] == '=')
            break;
        do
        {
            if (src[i])
                c = Chr2Base(src[i]);
            else
                c = 65;  //  字符串结束
        } while (c == 64);  //  跳过无效字符，如回车等

        if (c == 65)
            break;
        switch ( i % 4 )
        {
        case 0 :
            t = c << 2;
            break;
        case 1 :
            *p = (unsigned char)(t | (c >> 4));
            p++;
            t = ( unsigned char )( c << 4 );
            break;
        case 2 :
            *p = (unsigned char)(t | (c >> 2));
            p++;
            t = ( unsigned char )(c << 6);
            break;
        case 3 :
            *p = ( unsigned char )(t | c);
            p++;
            break;
        }
    }

    dst->resize(p - q);

    return true;
}

int Base64EncodeLen(int n)
{
    return (n + 2) / 3 * 4 + 1;
}

int Base64DecodeLen(int n)
{
    return n / 4 * 3 + 2;
}

} //end of namspace base64


int encrypto(char* buffer, int max_size, std::string* out_str)
{
    char endata[1024] = {0};
    char key[] = "V1.1.0_meansec";
    memcpy(endata, buffer, max_size);
    des_setparity(key);
    ecb_crypt(key, endata, 8, DES_ENCRYPT);
    std::string encry_str = std::string(endata);
    ecsm::base64::Encode(encry_str, out_str);
    return 0;
}

int decrypto(std::string thiz_en, std::string* out_str)
{
    char endata[1024] = {0};
    char key[] = "V1.1.0_meansec";
    std::string encry_str;
    ecsm::base64::Decode(thiz_en, &encry_str);
    des_setparity(key);
    memcpy(endata, encry_str.c_str(), encry_str.size());
    ecb_crypt(key, endata, 8, DES_DECRYPT);
    out_str->assign(endata);
    return 0;
}


} //end of namspace ecsm
