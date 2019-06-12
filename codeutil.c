#include "codeutil.h"
#include "utility.h"
#include "sha2.h"

static const uInt SHA512_LEN=SHA512_DIGEST_SIZE*2+1;
static const uInt LOWERLEN_DEFAULT = 6;
static const uInt UPPERLEN_DEFAULT = 2;
static const uInt DIGITLEN_DEFAULT = 1;
static const uInt SPECHLEN_DEFAULT = 1;

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
memcpy(temp2,s,utility_strlen(s));
	
for(i=0;i<LOOP;i++)
{
	memset(temp1,0x0,sizeof(temp1));
	utility_sha384(temp2,temp1);
	
	memset(temp2,0x0,sizeof(temp2));
	utility_invert(temp1,temp2,sizeof(temp2));
	
	memset(temp1,0x0,sizeof(temp1));
	utility_sha512(temp2,temp1);

	memset(temp2,0x0,sizeof(temp2));
	utility_invert(temp1,temp2,sizeof(temp2));
}

_splitstring(temp2,digit,alpha);
}

/* 将原始的密码串进行加工处理指定长度 */
static char* _basecode(const char* p,const char* q,char* new,uInt len)
{
int i=0;
	
	for(i=0;i<len;i++)
	{
		*(new+i) = utility_galpha(utility_sumchar(p)+utility_gdigit(q));
		if (i%2 == 0)
			p++;
		else
			q++;
	}
	
	return new;
}

/* 将密码串按要求加工*/
static char* _convert(const char* p,const char* q,char* dst,uInt len,uInt pwdLen,int flag)
{
int i,j;
char* ptr = dst;

    for(i = 0; i < len; p++,q++)
    {
        if ((utility_strlen(p) == 0) || (utility_strlen(q) == 0))
            break;

        j = (utility_sumchar(p) + utility_gdigit(q)) % pwdLen ;

        if (islower(*(dst+j)) != 0)
        {
            i++;
            switch(flag)
            {
                case 1:
                    *(dst+j) = utility_trandigit(*(p+j));
                    break;
                case 2:
                    *(dst+j) = *(p+j);
                    break;
                case 3:
                    *(dst+j) = toupper(*(dst+j));
                    break;
            }
        }
    }

    return ptr;
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
参数3：加密后的字符串
参数4：参数3的长度
*/
char* codeutil_password(const char* s,const char* pwdlen,char* code,size_t codelen)
{
char alpha_str[SHA512_LEN];
char digit_str[SHA512_LEN];
char* p = code;
uInt lowerLen = LOWERLEN_DEFAULT;
uInt upperLen = UPPERLEN_DEFAULT;
uInt digitLen = DIGITLEN_DEFAULT;
uInt spechLen = SPECHLEN_DEFAULT;
uInt passwordLen = lowerLen+upperLen+digitLen+spechLen;

if ((utility_strlen(s) == 0) || (utility_strlen(s) >= SHA512_LEN))
	return NULL;

if (utility_strlen(pwdlen) == 4) 
{
	lowerLen=utility_chtonum(pwdlen[0]);
	upperLen=utility_chtonum(pwdlen[1]);
	digitLen=utility_chtonum(pwdlen[2]);
	spechLen=utility_chtonum(pwdlen[3]);
}
else
{
	lowerLen = LOWERLEN_DEFAULT;
	upperLen = UPPERLEN_DEFAULT;
	digitLen = DIGITLEN_DEFAULT;
	spechLen = SPECHLEN_DEFAULT;
}

passwordLen = lowerLen+upperLen+digitLen+spechLen;

if (codelen < passwordLen)
	return NULL;

memset(alpha_str,0x0,sizeof(alpha_str));
memset(digit_str,0x0,sizeof(digit_str));

_rawcode(s,alpha_str,digit_str);
_basecode(digit_str,alpha_str,code,passwordLen);

_convert(digit_str,alpha_str,code,spechLen,passwordLen,1);
_convert(digit_str,alpha_str,code,digitLen,passwordLen,2);
_convert(digit_str,alpha_str,code,upperLen,passwordLen,3);

if (lowerLen > 0)
	_lowstrpos(code);

return p;
}

