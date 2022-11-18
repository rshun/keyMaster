#include "codeutil.h"
#include "utility.h"
#include "sha2.h"

typedef struct _keyLenStru keyinfo,*keyinfoPtr;
struct _keyLenStru
{
uInt alphalen;
uInt upperlen;
uInt digitlen;
uInt spechlen;
};
static const uInt SHA512_LEN=SHA512_DIGEST_SIZE*2+1;
static const char ALPHABET[]="abcdefghijklmnopqrstuvwxyz";
static const char DIGIT[]="0123456789";

/* 将密码长度分隔到指定字符串 
长度为3 第1位是字母 第2位是数字 第3位是特殊字符 
长度为4 前2位是字母 第3位是数字 第4位是特殊字符
除此之外 8位字母 1位数字 1位特殊字符
密码长度必须大于6,且必须包含字母或数字
大写字母占大于20%
*/
static size_t _splitKeyLen(const char* s,keyinfoPtr info)
{
size_t total;
int i;

	switch(util_strlen(s))
	{
		case 3:
			info->alphalen = util_ch2num(s[0]);
			info->digitlen = util_ch2num(s[1]);
			info->spechlen = util_ch2num(s[2]);
			break;
		case 4:
			info->alphalen = util_ch2num(s[0]) * 10 + util_ch2num(s[1]);
			info->digitlen = util_ch2num(s[2]);
			info->spechlen = util_ch2num(s[3]);
			if (info->alphalen > 52)
				info->alphalen = 8;
			break;
		default:
			info->alphalen = 8;
			info->digitlen = 1;
			info->spechlen = 1;
			break;
	}

	if ((info->alphalen==0) && (info->digitlen==0))
	{
		info->alphalen = 8;
		info->digitlen = 1;
		info->spechlen = 1;
	}


	if (info->alphalen+info->digitlen+info->spechlen < 6)
	{
		info->alphalen = 8;
		info->digitlen = 1;
		info->spechlen = 1;
	}

total = info->alphalen+info->digitlen+info->spechlen;

if (info->alphalen > 0)
{
	for(i=0;i<total;i++)
	{
		if ((float)i / total * 100 - UPPER_RATIO >= -0.004)
		{
			info->upperlen = i;
			info->alphalen = info->alphalen - i;
			break;
		}
	}
}

return total;
}

/* 去掉重复的字符串 */
static char _rmDupStr(char* str,uInt slen)
{
size_t len = util_strlen(str);
char value[util_strlen(ALPHABET)+1];
int result[26]={0};
int i,j,v=1;

memset(value,0x0,sizeof(value));
/* 统计每个字母的出现次数 */
for(i=0;i<len;i++)
{
	if (isalpha(str[i]))
		result[str[i]-'a']++;
}

/* 去掉重复字母 */
for(i=0,j=0;i<util_strlen(ALPHABET);i++)
{
	if (result[i] == 0) 
		value[j++] = ALPHABET[i];
}

for(i=0;i<len;i++)
	v += (str[i] * (i+slen));

return value[v % util_strlen(value)];
}

/* 去掉重复的数字  */
static char _rmDupDigit(char* str,uInt slen)
{
size_t len = util_strlen(str);
char value[util_strlen(DIGIT)+1];
int result[10]={0};
int i,j,v=1;

memset(value,0x0,sizeof(value));

/* 统计每个数字的次数 */
for(i=0;i<len;i++)
{
	if (isdigit(str[i]))
		result[str[i]-'0']++;
}

/* 去掉重复数字 */
for(i=0,j=0;i<util_strlen(DIGIT);i++)
{
	if (result[i] == 0) 
		value[j++] = DIGIT[i];
}

for(i=0;i<len;i++)
	v += (str[i] * (i+slen));

return value[v % util_strlen(value)];
}

static void _splitstring(const char* s,char* digit,char* alphabet)
{
    for(;*s!='\0';s++)
    {
        if (isdigit(*s))
            *digit++ = *s;

        if (isalpha(*s))
            *alphabet++ = *s;
    }
}

/* 生成原始的密码串*/
static void _rawcode(const char* s,char* alpha,char* digit)
{
int i;
char temp1[SHA512_LEN],temp2[SHA512_LEN];

memset(temp2,0x0,sizeof(temp2));
memcpy(temp2,s,util_strlen(s));
	
for(i=0;i<LOOP;i++)
{
	memset(temp1,0x0,sizeof(temp1));
	util_sha384(temp2,temp1);
	
	memset(temp2,0x0,sizeof(temp2));
	util_invert(temp1,temp2,sizeof(temp2));
	
	memset(temp1,0x0,sizeof(temp1));
	util_sha512(temp2,temp1,strlen(temp2));

	memset(temp2,0x0,sizeof(temp2));
	util_invert(temp1,temp2,sizeof(temp2));
}

_splitstring(temp2,digit,alpha);
}

/* 将原始的密码串进行加工处理指定长度 */
static char* _basecode(const char* p,const char* q,char* new,uInt len)
{
int i=0;
char *ptr = new;
char c;

	for(i=0;i<len;i++)
	{
		c =  util_galpha(util_sumchar(p)+util_gdigit(q));
		if (len < 26)
		{
			/*去掉重复的数字或字符串*/
			if (strchr(new,c) != NULL)
				c = _rmDupStr(new,len);
		}
		*(new+i) = c;
		if (i%2 == 0)
			p++;
		else
			q++;
	}

	return ptr;
}

/* 将密码串按要求加工*/
static char* _convert(const char* p,const char* q,char* dst,uInt len,uInt pwdLen,int flag)
{
int i,j;
char *ptr = dst;
char c;

/* 如果全是数字字符串,则循环更改 */
if (len == pwdLen)
{
	for(i = 0; i < len; p++,q++,i++)
	{
		if (i % 2 != 0)
			c = *(p+((util_sumchar(p)*util_gdigit(q)) %util_strlen(p)));
		else
			c = *(p+((util_gdigit(q)-util_sumchar(p)) %util_strlen(p)));
		
		if (strchr(dst,c) != NULL)
			c = _rmDupDigit(dst,len);

		*(dst+i) = c;
	}
}
else	/* 随机更改 */
{
    for(i = 0; i < len; p++,q++)
    {
        if ((util_strlen(p) == 0) || (util_strlen(q) == 0))
            break;

        j = (util_sumchar(p) + util_gdigit(q)) % pwdLen ;
		
        if (islower(*(dst+j)) != 0)
        {
            i++;
            switch(flag)
            {
                case 1:	/* 特殊字符 */
                    *(dst+j) = util_char2spec(*(p+j));
                    break;
                case 2: /* 数字 */
                    *(dst+j) = *(p+j);
                    break;
                case 3: /* 大写字符 */
                    *(dst+j) = toupper(*(dst+j));
                    break;
            }
        }
    }
}

return ptr;
}

/* 将密码中的特殊字符串改成指定的特殊字符串*/
static char* _specStr(char* s,const char* specstr)
{
int i=0;
char* p = s;

while(*(s+i) != '\0')
{
	if (isdigit(*(s+i)) || isalpha(*(s+i)) || isupper(*(s+i)))
	{
		i++;
		continue;
	}

	if (strchr(specstr,*(s+i)) == NULL)
	{
		*(s+i) = specstr[i % (util_strlen(specstr))];
	}
	i++;
}

return p;
}

/*若首位非字母,则将字符串第一个字母和首位互换*/
static char* _lowstrpos(char* s)
{
int i = 0;
char r = s[0];
char* p = s;

while(*(s+i) != '\0')
{
    if (isalpha(*(s+i)))
        break;

    i++;
}

s[0] = s[i];
s[i] = r;

return p;

}

/*
参数1：待加密字符串
参数2：密码长度
参数3：是否有指定的特殊字符串 为空不指定
参数4：加密后的字符串
参数5：参数4的长度
*/
char* codeutil_password(const char* s,const char* pwdlen,const char* spec,char* code,size_t codelen)
{
char alpha_str[SHA512_LEN];
char digit_str[SHA512_LEN];
char* p = code;
size_t passwordLen;
keyinfo myKeyInfo;

if ((util_strlen(s) == 0) || (util_strlen(s) >= SHA512_LEN))
	return NULL;

memset(&myKeyInfo,0x0,sizeof(myKeyInfo));
passwordLen=_splitKeyLen(pwdlen,&myKeyInfo);

if (codelen <= passwordLen)
	return NULL;

memset(alpha_str,0x0,sizeof(alpha_str));
memset(digit_str,0x0,sizeof(digit_str));

/*
1、生成最原始的密钥串
2、按照密码的长度做切割
3、依照密码的类型对密码串转换
4、判断首字母是否为字母
5、判断是否指定特殊串
*/
_rawcode(s,alpha_str,digit_str);
_basecode(digit_str,alpha_str,code,passwordLen);

_convert(digit_str,alpha_str,code,myKeyInfo.spechlen,passwordLen,1);
_convert(digit_str,alpha_str,code,myKeyInfo.digitlen,passwordLen,2);
_convert(digit_str,alpha_str,code,myKeyInfo.upperlen,passwordLen,3);

if (myKeyInfo.alphalen > 0)
	_lowstrpos(code);

if (util_strlen(spec) > 0)
	_specStr(code,spec);

return p;
}
