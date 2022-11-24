#include "utility.h"
#include "sha2.h"
#include "aes.h"
#include "base64.h"

void util_splitbuff(const char* buff,char* index,size_t index_len,char* value,size_t value_len)
{
char* p=NULL;
int len = strlen(buff);

if ((p = strchr(buff,'=')) == NULL)
	return;

if (index_len > len-strlen(p))
	strncpy(index,buff,len-strlen(p));

snprintf(value,value_len,"%s",p+1);

return;
}

/*
功能: 删除字符串前后的空格
*/
char* util_trim(char* _str)
{
size_t len;
char* end=NULL;
char* front=_str;

if (!_str) return _str;

while (isspace(*_str)) _str++;

if ((len = strlen(_str)) == 0) return _str;

end = _str + len - 1;

while (isspace(*end)) end--;

if (end != (_str + len - 1))
  *(end+1) = '\0';

end = _str;
while (*end) *front++ = *end++;
*front = '\0';

return _str;
}

/* 字符串长度 */
size_t util_strlen(const char* _s)
{
	if (_s == NULL)
		return 0;
	else
		return strlen(_s);
}

char* util_sha384(const char* s,char* sha384str)
{
int i;
uChar digest[SHA384_DIGEST_SIZE];
char* p = sha384str;

memset(digest,0x0,sizeof(digest));
sha384((const uChar*)s,util_strlen(s),digest);

for (i=0;i<SHA384_DIGEST_SIZE;i++)
	sprintf(&sha384str[i*2], "%02x", (uInt)digest[i]);

return p;
}	

char* util_sha512(const char* s,char* sha512str,size_t len)
{
uChar digest[SHA512_DIGEST_SIZE];
int i;
char* p = sha512str;

memset(digest,0x0,sizeof(digest));
sha512((const uChar*)s,len,digest);

for (i=0;i<SHA512_DIGEST_SIZE;i++)
	sprintf(&sha512str[i*2], "%02x", (uInt)digest[i]);

return p;	
}

/* 将数字转换成特殊字符 */
char util_num2spec(uInt s)
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
uInt util_ch2num(char s)
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
char util_char2spec(char s)
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
char util_galpha(uInt v)
{
    return 97 + (v%26);
}

/* 将字符串的ascii值相加 */
uInt util_gdigit(const char* s)
{
uInt v=0;

if (util_strlen(s) == 0)
    return v;

while (*s != '\0')
    v += *s++;

return v;
}

/* 将字符串中的各数字相加 */
uInt util_sumchar(const char* s)
{
uInt v = 0;

if (util_strlen(s) == 0)
    return v;

while (*s != '\0')
    v += util_ch2num(*s++);

return v;
}

char* util_tolower(char* p_str)
{
char* _s = p_str;

if (p_str)
{
  for(;*p_str != '\0';p_str++)
    *p_str = tolower(*p_str);
}

return _s;
}

char* util_toupper(char* p_str)
{
char* _s = p_str;

if (p_str)
{
  for(;*p_str != '\0';p_str++)
    *p_str = toupper(*p_str);
}

return _s;
}

char* util_invert(const char* s1,char* s2,size_t len)
{
size_t s_len = util_strlen(s1);
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

char* util_strrev(char* s1)
{
size_t s_len = util_strlen(s1);
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
off_t util_getfilesize(const char* filename)
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
int util_isdigitstr(const char* str)
{
if (!util_strlen(str))
  return -1;

while (*str != '\0')
{
  if (!isdigit(*str++))
    return -1;
}

return 0;
}

void util_free(void** p_ptr)
{
  if ((p_ptr != NULL) && (*p_ptr != NULL))
  {
    free(*p_ptr);
    *p_ptr = NULL;
  }
}

char* util_put2Value(char* _s,char** _d)
{
size_t len = util_strlen(_s)+1;

*_d = NULL;
if (len == 1)
  return NULL;

if ((*_d = (char*)malloc(len)) == NULL)
{
	printf("malloc is error,len=%zd,[%s]\n",len,strerror(errno));
	return NULL;
}

memset(*_d,0x0,len);
strncpy(*_d,_s,len-1);

return *_d;
}

uInt util_getKeyLen(const char* keylen)
{
uInt r = 0;
uInt len = util_strlen(keylen);
int i=0;

if (len == 4)
{
	r=(keylen[0]-48)*10;
	i=1;
}

for(;i<len;i++)
{
	switch(keylen[i])
	{
        case '1':r+=1;break;
        case '2':r+=2;break;
        case '3':r+=3;break;
        case '4':r+=4;break;
        case '5':r+=5;break;
        case '6':r+=6;break;
        case '7':r+=7;break;
        case '8':r+=8;break;
        case '9':r+=9;break;
        default:break;		
	}
}

return r;
}

int util_initValue(char** s,size_t len)
{
	if ((*s = (char*)malloc(len)) == NULL)
	{
		printf("malloc is error,[%s]\n",strerror(errno));
		return -1;
	}
	
	memset(*s,0x0,len);
	return 0;
}

/*
将ascii字符转成16进制
*/
uChar* util_str2hex(const char* s,uChar* result,size_t len)
{
unsigned char *p = result;

for (int i=0;i<strlen(s);i++)
    snprintf((char*)&result[i*2],len, "%02x", (uInt)s[i]);

return p;
}

/* 编码base64 
参数1: 源串
参数2: 源串长度
参数3: 编码后存放字符串
参数4: 参数3的长度

返回: -1长度不足,其余编码后的长度
*/
int util_base64enc(const char* src,int src_len,char* d,int len)
{
int des_len=Base64encode_len(src_len);  /* 长度包括字符串最后一位0x0 */

if (des_len >= len)
	return -1;

return Base64encode(d,src,src_len);
}

/* 解码base64
参数1: 源串
参数2: 源串长度
参数3: 解码后存放字符串
参数4: 参数3的长度

返回: -1长度不足,其余解码后的长度
*/
int util_base64decode(const char* src,int src_len,char* d,int len)
{
int des_len=Base64decode_len(src);

if (des_len >= len)
	return -1;

return Base64decode(d,src);
}

/* 
下面三个函数是pkcs7补齐
*/
int pkcs7_padding_pad_buffer( uint8_t *buffer,  size_t data_length, size_t buffer_size, uint8_t modulus ){
  uint8_t pad_byte = modulus - ( data_length % modulus ) ;
  if( data_length + pad_byte > buffer_size ){
    return -pad_byte;
  }
  int i = 0;
  while( i <  pad_byte){
    buffer[data_length+i] = pad_byte;
    i++;
  }
  return pad_byte;
}

int pkcs7_padding_valid( uint8_t *buffer, size_t data_length, size_t buffer_size, uint8_t modulus ){
  uint8_t expected_pad_byte = modulus - ( data_length % modulus ) ;
  if( data_length + expected_pad_byte > buffer_size ){
    return 0;
  }
  int i = 0;
  while( i < expected_pad_byte ){
    if( buffer[data_length + i] != expected_pad_byte){
      return 0;
    }
    i++;
  }
  return 1;
}

size_t pkcs7_padding_data_length( uint8_t * buffer, size_t buffer_size, uint8_t modulus ){
  /* test for valid buffer size */
  if( buffer_size % modulus != 0 ||
    buffer_size < modulus ){
    return 0;
  }
  uint8_t padding_value;
  padding_value = buffer[buffer_size-1];
  /* test for valid padding value */
  if( padding_value < 1 || padding_value > modulus ){
    return buffer_size;
  }
  /* buffer must be at least padding_value + 1 in size */
  if( buffer_size < padding_value + 1 ){
    return -1;
  }
  uint8_t count = 1;
  buffer_size --;
  for( ; count  < padding_value ; count++){
    buffer_size --;
    if( buffer[buffer_size] != padding_value ){
      return -2;
    }
  }
  return buffer_size;
}

/*
功能: aes256加密,模式cbc,填充使用pkcs7
参数1: 密钥
参数2: 明文
参数3: 向量iv
参数4: 密文
参数5: 密文长度

在原始数据长度为 32 的整数倍时
假如原始数据长度等于 32n，则使用 NoPadding 时加密后数据长度等于 32n，其它情况下加密数据长度等于 32*(n+1)。
在不足 32 的整数倍的情况下
假如原始数据长度等于 32n+m [其中 m 小于32]，除了 NoPadding 填充之外的任何方式，加密数据长度都等于32*(n+1)

Base64长度为=bytestring * (4 / 3)，不能被3整除的，加到最小被3整除的数.
返回: 小于0,加密错误,大于0,base64编码后的密文
*/
int encrypt_aes256_cbc(const char* key,const char* plaintxt,const char* iv,char* ciphertxt,size_t cipherlen)
{  
int plaintxt_Len=strlen(plaintxt);
int key_Len=strlen(key);
int pad_plainLen=plaintxt_Len;
int pad_keyLen=key_Len;
uint8_t pad_IV[AES_KEYLEN];
uint8_t* pad_Key=NULL;
uint8_t* pad_Plaintxt=NULL;
struct AES_ctx ctx;
int len=0;

/* 计算明文和密钥长度，设置长度为AES_KEYLEN的整数倍*/
if (plaintxt_Len % AES_KEYLEN)
  pad_plainLen+=AES_KEYLEN-(plaintxt_Len % AES_KEYLEN);

if (key_Len % AES_KEYLEN)
  pad_keyLen += AES_KEYLEN - (key_Len % AES_KEYLEN);

if ((cipherlen < 0) || (cipherlen < pad_plainLen))
  return -1;

if ((pad_Key = (uint8_t*)malloc(pad_keyLen)) == NULL)
	return -1;

if ((pad_Plaintxt = (uint8_t*)malloc(pad_plainLen)) == NULL)
{
	util_free((void*)&pad_Key);
	return -1;
}

memset( pad_Key, 0x0, pad_keyLen);
memset( pad_Plaintxt, 0x0, pad_plainLen);
memset( pad_IV, 0x0, sizeof(pad_IV));

memcpy(pad_Plaintxt,plaintxt,plaintxt_Len);
memcpy(pad_Key,key,key_Len);
if (strlen(iv) < AES_KEYLEN)
{
    memcpy(pad_IV,iv,strlen(iv));
    pkcs7_padding_pad_buffer( pad_IV, strlen(iv),sizeof(pad_IV),AES_KEYLEN);
}
else
{
    memcpy(pad_IV,iv,AES_KEYLEN);
}

/*填充待加密的明文,密钥和向量IV*/
pkcs7_padding_pad_buffer( pad_Plaintxt, plaintxt_Len, pad_plainLen, AES_KEYLEN );
pkcs7_padding_pad_buffer( pad_Key, key_Len,pad_keyLen,AES_KEYLEN);
pkcs7_padding_pad_buffer( pad_IV, strlen(iv),sizeof(pad_IV),AES_KEYLEN);

AES_init_ctx_iv(&ctx, pad_Key, pad_IV);
AES_CBC_encrypt_buffer(&ctx, pad_Plaintxt, pad_plainLen);

len = util_base64enc((const char*)pad_Plaintxt,pad_plainLen,ciphertxt,cipherlen);

util_free((void*)&pad_Key);
util_free((void*)&pad_Plaintxt);

return len;
}

/*
aes256解密，模式cbc,填充使用pkcs7
参数1: 密钥
参数2: base64密文
参数3: 密文长度
参数4: 向量iv
参数5: 明文
参数6: 明文长度

返回: -1长度不足，其余明文长度
*/

int decrypt_aes256_cbc(const char* key,const char* base64buf,size_t buflen,const char* iv,char* plaintxt,size_t plainlen)
{
uint8_t ciphertxt[buflen];
uint8_t* pad_Key=NULL;
uint8_t pad_IV[AES_KEYLEN];
size_t actualLength;
int cipherlen;
int key_Len=strlen(key);
int pad_keyLen=key_Len;
struct AES_ctx ctx;

/* 将base64解码成密文 */
memset(ciphertxt,0x0,sizeof(ciphertxt));
cipherlen = util_base64decode(base64buf,buflen,(char*)ciphertxt,sizeof(ciphertxt));
if (cipherlen < 0)
    return -1;

/* 根据AES算法计算待补足的Key长度 */
if (key_Len % AES_KEYLEN)
    pad_keyLen += AES_KEYLEN - (key_Len % AES_KEYLEN);

if ((pad_Key = (uint8_t*)malloc(pad_keyLen)) == NULL)
    return -1;

/* 补齐Key */
memset(pad_Key, 0x0, pad_keyLen);
memcpy(pad_Key,key,key_Len);
pkcs7_padding_pad_buffer( pad_Key, key_Len,pad_keyLen,AES_KEYLEN);

/* 补齐IV */
memset( pad_IV, 0x0, sizeof(pad_IV));
if (strlen(iv) < AES_KEYLEN)
{
    memcpy(pad_IV,iv,strlen(iv));
    pkcs7_padding_pad_buffer( pad_IV, strlen(iv),sizeof(pad_IV),AES_KEYLEN);
}
else
{
    memcpy(pad_IV,iv,AES_KEYLEN);
}

AES_init_ctx_iv(&ctx, pad_Key, pad_IV);
AES_CBC_decrypt_buffer(&ctx, ciphertxt, cipherlen);

actualLength = pkcs7_padding_data_length( ciphertxt, cipherlen, AES_KEYLEN);

ciphertxt[actualLength]='\0';
snprintf(plaintxt,plainlen,"%s",ciphertxt);

util_free((void*)&pad_Key);
return actualLength;
}
