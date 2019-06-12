#include "myKey.h"
#include "cJSON.h"
#include "codeutil.h"

const char* JSON_LABEL[]={"cnName","enName","webAddr","userID","keyLen","updateTime","webIcon"};
const char HTTP_HEAD[]="http://";
const char HTTPS_HEAD[]="https://";
const char WWW_ADDR[]="www.";
const char BBS_ADDR[]="bbs.";

static size_t _strlen(const char* _s)
{
	if (_s == NULL)
		return 0;
	else
		return strlen(_s);
}

static char* tolowerstr(char* p_str)
{
char* _s = p_str;

if (p_str)
{
  for(;*p_str != '\0';p_str++)
    *p_str = tolower(*p_str);
}

return _s;
}

/*只保留域名地址*/
const char* _RawAddr(const char* s,char* r,size_t rlen)
{
char *p = NULL;
size_t http_len = _strlen(HTTP_HEAD);
size_t https_len = _strlen(HTTPS_HEAD);
size_t www_len= _strlen(WWW_ADDR);
size_t bbs_len = _strlen(BBS_ADDR);
size_t len = _strlen(s);
size_t flag;

if (( p =strstr(s,HTTP_HEAD)) != NULL)
    flag = http_len;
else if (( p =strstr(s,HTTPS_HEAD)) != NULL)
    flag = https_len;
else
    flag = 0;

if (( p = strstr(s,WWW_ADDR)) != NULL)
    strncpy(r,s+flag+www_len,len-flag-www_len);
else if (( p = strstr(s,BBS_ADDR)) != NULL)
    strncpy(r,s+flag+bbs_len,len-flag-bbs_len);
else
    strncpy(r,s+flag,len-flag);

do
{
    if (*r == '/') *r = '\0';
}while (*r++ != '\0');

return r;
}

static void _free(void** p_ptr)
{
  if ((p_ptr != NULL) && (*p_ptr != NULL))
  {
    free(*p_ptr);
    *p_ptr = NULL;
  }
}

/* 获取文件大小 */
static off_t _getFileSize(const char* filename)
{
struct stat _buf;

    if (stat(filename,&_buf) < 0)
    {
        printf("stat [%s] is error,[%s]\n",filename,strerror(errno));
        return 0;
    }

    return _buf.st_size;
}

static void deallocate(keyinfoPtr value)
{
_free((void**)&value->cnName);
_free((void**)&value->enName);
_free((void**)&value->webAddr);
_free((void**)&value->userID);
_free((void**)&value->keyLen);
_free((void**)&value->updateTime);
}

static char* _put2Value(char* _s,char** _d)
{
size_t len = _strlen(_s)+1;

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

static uInt _getKeyLen(const char* keylen)
{
uInt r = 0;
uInt len = _strlen(keylen);
int i;

for(i=0;i<len;i++)
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

/*校验密码生成次数,如果为空赋默认值*/
static char* _initTimes(char** value)
{

if(_strlen(*value) == 0)
{
	if ((*value = (char*)malloc(2)) == NULL)
	{
		printf("updateTime malloc is error,[%s]\n",strerror(errno));
		return NULL;
	}
	
	memset(*value,0x0,2);
	*value[0] = '1';
}

if (!isdigit(*value[0]))
	*value[0] = '1';

return *value;
}

static int _initValue(char** s,size_t len)
{
	if ((*s = (char*)malloc(len)) == NULL)
	{
		printf("malloc is error,[%s]\n",strerror(errno));
		return -1;
	}
	
	memset(*s,0x0,len);
	return 0;
}

/*校验密码长度,如果为空赋默认值*/
static char* _initKeylen(char** value)
{
uInt len = _strlen(DEFAULT_PWDLEN) + 1;

if(_strlen(*value) == 0)
{
	if ((*value = (char*)malloc(len)) == NULL)
	{
		printf("updateTime malloc is error,[%s]\n",strerror(errno));
		return NULL;
	}
	
	memset(*value,0x0,len);
	strncpy(*value,DEFAULT_PWDLEN,len - 1);
}

return *value;
}

static int _getKeyData(const char* jsonbuf,const char* primary)
{
cJSON *root,*array,*value;
keyinfoPtr ptrJson;
int i,j,num,addrlen,len;
int labelLen=sizeof(JSON_LABEL)/sizeof(JSON_LABEL[0]);
char* password,*code,*addr;

if ((root = cJSON_Parse(jsonbuf)) == NULL)
{
	printf("root error [%s]\n",cJSON_GetErrorPtr());
	return -1;
}

if ((ptrJson = (keyinfoPtr)malloc(sizeof(keyinfo))) == NULL)
{
	printf("malloc is error,[%s]\n",strerror(errno));
	cJSON_Delete(root);
	return -1;
}

num = cJSON_GetArraySize(root);
for(i=0;i<num;i++)
{
	if ((array = cJSON_GetArrayItem(root,i)) == NULL)
	{
		printf("array error [%s]\n",cJSON_GetErrorPtr());
		cJSON_Delete(root);
		return -1;
	}

 	for(j=0;j<labelLen;j++)
	{
 		value = cJSON_GetObjectItem(array,JSON_LABEL[j]);
		switch(j)
		{
			case 0:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->cnName);
				break;
			case 1:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->enName);
				break;
			case 2:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->webAddr);
				tolowerstr(ptrJson->webAddr);
				break;
			case 3:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->userID);
				break;
			case 4:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->keyLen);
				_initKeylen(&ptrJson->keyLen);
				break;
			case 5:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->updateTime);
				_initTimes(&ptrJson->updateTime);
				break;
			case 6:
				_put2Value(cJSON_GetStringValue(value),&ptrJson->webIcon);				
				break;
		}
	}
	
	addrlen = _strlen(ptrJson->webAddr);
	if ((_strlen(ptrJson->userID) > 0) && (addrlen > 0))
	{
		len = _getKeyLen(ptrJson->keyLen)+1;
		_initValue(&password,len);
		
		_initValue(&code,addrlen+_strlen(ptrJson->userID)+_strlen(ptrJson->updateTime)+_strlen(primary) + 1);
		
		_initValue(&addr,addrlen+1);

		_RawAddr(ptrJson->webAddr,addr,addrlen+1);

		sprintf(code,"%s%s%s%s",addr,primary,ptrJson->userID,ptrJson->updateTime);
		//printf("code=[%s]\n",code);
		codeutil_password(code,ptrJson->keyLen,password,len);
		printf("[%s]\t[%s]\tuser=[%s]\tpassword=[%s]\n",ptrJson->enName,ptrJson->cnName,ptrJson->userID,password);
	}
/*
	_free((void**)code);
	_free((void**)password);
	_free((void**)addr);
*/
	deallocate(ptrJson);
}
_free((void**)ptrJson);

cJSON_Delete(root);
return 0;
}

int main(int argc,char* argv[])
{
FILE *fp;
char filename[255+1];
char* filebuf;
off_t fileLen;

if (argc < 3)
{
	printf("usage:%s user primaryKey [keyword]\n",argv[0]);
	exit(-1);
}

memset(filename,0x0,sizeof(filename));
snprintf(filename,sizeof(filename),"%s.json",argv[1]);

if ((fileLen = _getFileSize(filename)) == 0)
	exit(-1);

if ((filebuf = (char*)malloc(fileLen+1)) == NULL)
{
	printf("malloc is error,[%ld],[%s]\n",fileLen,strerror(errno));
	exit(-1);
}

if ((fp = fopen(filename,"r")) == NULL)
{
	printf("open %s is error,[%s]\n",filename,strerror(errno));
	free(filebuf);
	exit(-1);
}

memset(filebuf,0x0,fileLen+1);
fread(filebuf,fileLen,1,fp);
fclose(fp);

_getKeyData(filebuf,argv[2]);

free(filebuf);

return 0;
}
