#include "utility.h"
#include "sha2.h"

/* 字符串长度 */
size_t utility_strlen(const char* _s)
{
	if (_s == NULL)
		return 0;
	else
		return strlen(_s);
}

char* utility_sha384(const char* s,char* sha384str)
{
int i;
uChar digest[SHA384_DIGEST_SIZE];
char* p = sha384str;

memset(digest,0x0,sizeof(digest));
sha384((const uChar*)s,utility_strlen(s),digest);

for (i=0;i<SHA384_DIGEST_SIZE;i++)
	sprintf(&sha384str[i*2], "%02x", (uInt)digest[i]);

return p;
}	

char* utility_sha512(const char* s,char* sha512str)
{
uChar digest[SHA512_DIGEST_SIZE];
int i;
char* p = sha512str;

memset(digest,0x0,sizeof(digest));
sha512((const uChar*)s,utility_strlen(s),digest);

for (i=0;i<SHA512_DIGEST_SIZE;i++)
	sprintf(&sha512str[i*2], "%02x", (uInt)digest[i]);

return p;	
}

/* 将数字转换成特殊字符 */
char utility_num2spec(uInt s)
{
char v='#';

    switch(s%10)
    {
        case 1:v='(';break;
        case 2:v=')';break;
        case 3:v='#';break;
        case 4:v='%';break;
        case 5:v='!';break;
        case 6:v='+';break;
        case 7:v='-';break;
        case 8:v='$';break;
        case 9:v=':';break;
        case 0:v=';';break;
        default:break;
    }

    return v;
}

/* 将字符转成数字 */
uInt utility_ch2num(char s)
{
uInt v=0;

    switch(s)
    {
        case '1':v=1;break;
        case '2':v=2;break;
        case '3':v=3;break;
        case '4':v=4;break;
        case '5':v=5;break;
        case '6':v=6;break;
        case '7':v=7;break;
        case '8':v=8;break;
        case '9':v=9;break;
        default:break;
    }

    return v;
}

/* 将字符转成特殊字符 */
char utility_char2spec(char s)
{
char v='0';

    switch(s)
    {
        case '1':v='!';break;
        case '2':v='@';break;
        case '3':v='#';break;
        case '4':v='$';break;
        case '5':v='%';break;
        case '6':v=';';break;
        case '7':v=':';break;
        case '8':v='+';break;
        case '9':v='(';break;
        case '0':v=')';break;
        default:break;
    }

    return v;
}

/* 将数字转成字母 */
char utility_galpha(uInt v)
{
    return 97 + (v%26);
}

/* 将字符串的ascii值相加 */
uInt utility_gdigit(const char* s)
{
uInt v=0;

if (utility_strlen(s) == 0)
    return v;

    while (*s != '\0')
        v += *s++;

    return v;
}

/* 将字符串中的各数字相加 */
uInt utility_sumchar(const char* s)
{
uInt v = 0;

if (utility_strlen(s) == 0)
    return v;

    while (*s != '\0')
        v += utility_ch2num(*s++);

    return v;
}

char* utility_tolower(char* p_str)
{
char* _s = p_str;

if (p_str)
{
  for(;*p_str != '\0';p_str++)
    *p_str = tolower(*p_str);
}

return _s;
}

char* utility_toupper(char* p_str)
{
char* _s = p_str;

if (p_str)
{
  for(;*p_str != '\0';p_str++)
    *p_str = toupper(*p_str);
}

return _s;
}

char* utility_invert(const char* s1,char* s2,size_t len)
{
size_t s_len = utility_strlen(s1);
int i,j;

if ((s_len == 0) || (len == 1) || (len == 0))
	return s2;

if (s_len >= len)
	s_len = len - 1;

for(i=0,j=s_len;i<s_len;i++,j--)
	s2[i]=s1[j - 1];

s2[s_len]=0;
return s2;
}

char* utility_strrev(char* s1)
{
size_t s_len = utility_strlen(s1);
int i;
char *ptr = s1;
char c;

if (s_len <= 2)
	return ptr;

for(i=0;i<s_len / 2;i++)
{
	c = s1[i];
	s1[i] = s1[s_len - 1 -i];
	s1[s_len-1-i] = c;
}

return ptr;
}

/* 获取文件大小 */
off_t utility_getfilesize(const char* filename)
{
struct stat _buf;

    if (stat(filename,&_buf) < 0)
    {
        printf("stat [%s] is error,[%s]\n",filename,strerror(errno));
        return 0;
    }

    return _buf.st_size;
}

/* 判断是否是数字字符串 */
int utility_isdigitstr(const char* str)
{
if (!utility_strlen(str))
  return -1;

while (*str != '\0')
{
  if (!isdigit(*str++))
    return -1;
}

return 0;
}
