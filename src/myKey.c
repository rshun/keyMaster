#include "myKey.h"
#include "cJSON.h"
#include "codeutil.h"
#include "utility.h"

const char* JSON_LABEL[]={"cnName","enName","webAddr","userID","keyLen","updateTime","keyType","allowSpec","webIcon"};
const char HTTP_HEAD[]="http://";
const char HTTPS_HEAD[]="https://";
const char WWW_ADDR[]="www.";
const char BBS_ADDR[]="bbs.";

/*	只保留域名地址,去掉二级域名
参数: https://www.google.com/
返回: google.com
*/
const char* _RawAddr(const char* s,char* r,size_t rlen)
{
char *p = NULL;
size_t http_len = util_strlen(HTTP_HEAD);
size_t https_len = util_strlen(HTTPS_HEAD);
size_t www_len= util_strlen(WWW_ADDR);
size_t bbs_len = util_strlen(BBS_ADDR);
size_t len = util_strlen(s);
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

static void deallocate(keyinfoPtr value)
{
util_free((void**)&value->cnName);
util_free((void**)&value->enName);
util_free((void**)&value->webAddr);
util_free((void**)&value->userID);
util_free((void**)&value->keyLen);
util_free((void**)&value->updateTime);
util_free((void**)&value->keyType);
util_free((void**)&value->allowSpec);
}

/*校验密码生成次数,如果为空赋默认值*/
static char* _initTimes(char** value)
{

if(util_strlen(*value) == 0)
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

/*
功能:匹配关键字(不区分大小写)
根据输入值，在中文名称和网址中匹配是否存在,存在返回1,不存在返回0
 */
static int compValue(keyinfoPtr ptrJson,const char* keyWord)
{
char* tmp=NULL;
char newvalue[strlen(keyWord)+1];

if (strstr(ptrJson->cnName,keyWord) != NULL)
	return 1;

util_put2Value(ptrJson->enName,&tmp);
if (tmp == NULL)
	return 0;

memset(newvalue,0x0,sizeof(newvalue));
snprintf(newvalue,sizeof(newvalue),"%s",keyWord);
util_tolower(newvalue);
util_tolower(tmp);

if (strstr(tmp,newvalue) != NULL)
{
	util_free((void*)&tmp);
	return 1;
}
util_free((void*)&tmp);

util_put2Value(ptrJson->webAddr,&tmp);
if (tmp == NULL)
	return 0;

util_tolower(tmp);
if (strstr(tmp,newvalue) != NULL)
{
	util_free((void*)&tmp);
	return 1;
}

util_free((void*)&tmp);
return 0;
}

/*校验密码长度,如果为空赋默认值*/
static char* _initKeylen(char** value)
{
uInt len = util_strlen(DEFAULT_PWDLEN) + 1;

if(util_strlen(*value) == 0)
{
	if ((*value = (char*)malloc(len)) == NULL)
	{
		printf("updateTime malloc is error,[%s]\n",strerror(errno));
		return NULL;
	}
	
	memset(*value,0x0,len);
	strncpy(*value,DEFAULT_PWDLEN,len - 1);
}
else
{
	if (util_isdigitstr(*value) < 0)
	{
		memset(*value,0x0,len);
		strncpy(*value,DEFAULT_PWDLEN,len - 1);
	}
}
return *value;
}

static int _getKeyData(const char* jsonbuf,const char* primary,const char* keyword)
{
cJSON *root,*array,*value;
keyinfoPtr ptrJson;
int i,j,num,addrlen,len;
int labelLen=sizeof(JSON_LABEL)/sizeof(JSON_LABEL[0]);
char* password,*code,*addr;
char userid[100];

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
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->cnName);
				break;
			case 1:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->enName);
				break;
			case 2:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->webAddr);
				util_tolower(ptrJson->webAddr);
				break;
			case 3:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->userID);
				break;
			case 4:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->keyLen);
				_initKeylen(&ptrJson->keyLen);
				break;
			case 5:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->updateTime);
				_initTimes(&ptrJson->updateTime);
				break;
			case 6:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->keyType);
				break;
			case 7:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->allowSpec);
				break;
			case 8:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->webIcon);				
				break;
		}
	}

	if (compValue(ptrJson,keyword) > 0)
	{
		if ((ptrJson->userID == NULL) || (strlen(ptrJson->userID) == 0))
		{
			printf("input userid:");
			memset(userid,0x0,sizeof(userid));
			scanf("%s",userid);
			util_put2Value(userid,&ptrJson->userID);
		}
		addrlen = util_strlen(ptrJson->webAddr);
		if ((util_strlen(ptrJson->userID) > 0) && (addrlen > 0))
		{
			len = util_getKeyLen(ptrJson->keyLen)+1;
			util_initValue(&password,len);
			
			util_initValue(&code,addrlen+util_strlen(ptrJson->userID)+util_strlen(ptrJson->updateTime)+util_strlen(primary) + 1);
			
			util_initValue(&addr,addrlen+1);

			_RawAddr(ptrJson->webAddr,addr,addrlen+1);
/* 如果密钥类型为空,
原始加密串组成:地址+主密钥+用户名+更新次数
原始加密串组成:地址+主密钥+用户名+更新次数+密钥类型
*/
			if (ptrJson->keyType == NULL)
				sprintf(code,"%s%s%s%s",addr,primary,ptrJson->userID,ptrJson->updateTime);
			else	
				sprintf(code,"%s%s%s%s%s",addr,primary,ptrJson->userID,ptrJson->updateTime,ptrJson->keyType);

			codeutil_password(code,ptrJson->keyLen,ptrJson->allowSpec,password,len);
			printf("[%s]\t[%s]\tuser=[%s]\tpassword=[%s]\n",ptrJson->enName,ptrJson->cnName,ptrJson->userID,password);
			
			util_free((void*)&password);
			util_free((void*)&code);
			util_free((void*)&addr);
		}
	}
	deallocate(ptrJson);
}
util_free((void**)ptrJson);

cJSON_Delete(root);
return 0;
}

/*
功能: 根据输入用户名，返回对应的用户文件
0-成功
-1-失败
*/
static int parseUser(const char* userid,char** userfile)
{
char filename[255];
cJSON *root,*array;
FILE *fp;
char* buff;
int i,num;
off_t fileLen;

memset(filename,0x0,sizeof(filename));
snprintf(filename,sizeof(filename),"user.json");
if ((fileLen = util_getfilesize(filename)) == 0)
	return -1;

if ((buff = (char*)malloc(fileLen+1)) == NULL)
{
	printf("malloc is error,[%ld],[%s]\n",fileLen,strerror(errno));
	return -1;
}

if ((fp =fopen(filename,"r")) == NULL)
{
	fprintf(stderr,"open [%s] is error,[%s]\n",filename,strerror(errno));
	util_free((void*)&buff);
	return -1;
}
memset(buff,0x0,fileLen+1);
fread(buff,fileLen+1,1,fp);
fclose(fp);

if ((root = cJSON_Parse(buff)) == NULL)
{
	printf("root error [%s]\n",cJSON_GetErrorPtr());
	util_free((void*)&buff);
	return -1;
}

num = cJSON_GetArraySize(root);
for(i=0;i<num;i++)
{
	if ((array = cJSON_GetArrayItem(root,i)) == NULL)
	{
		printf("array error [%s]\n",cJSON_GetErrorPtr());
		cJSON_Delete(root);
		util_free((void*)&buff);
		return -1;
	}

	if (strncasecmp(cJSON_GetStringValue(cJSON_GetObjectItem(array,"userID")),userid,strlen(userid)) == 0)
	{
		util_put2Value(cJSON_GetStringValue(cJSON_GetObjectItem(array,"filename")),userfile);
		cJSON_Delete(root);
		util_free((void*)&buff);
		return 0;
	}
}

util_free((void*)&buff);
return -1;
}

int main(int argc,char* argv[])
{
FILE *fp;
char password[100];
char *filebuf=NULL,*filename=NULL;
off_t fileLen;

if (argc < 3)
{
	printf("usage:%s user keyword\n",argv[0]);
	exit(-1);
}

if (parseUser(argv[1],&filename) < 0)
{
	printf("[%s]file is not exists\n",argv[1]);
	util_free((void*)&filename);
	exit(-1);
}

if (filename == NULL)
{
	util_free((void*)&filename);
	exit(-1);
}

if ((fileLen = util_getfilesize(filename)) == 0)
{
	printf("[%s] is empty\n",filename);
	util_free((void*)&filename);
	exit(-1);
}

if ((filebuf = (char*)malloc(fileLen+1)) == NULL)
{
	printf("malloc is error,[%ld],[%s]\n",fileLen,strerror(errno));
	util_free((void*)&filename);
	exit(-1);
}

if ((fp = fopen(filename,"r")) == NULL)
{
	printf("open %s is error,[%s]\n",filename,strerror(errno));
	util_free((void*)&filebuf);
	util_free((void*)&filename);
	exit(-1);
}
util_free((void*)&filename);

memset(filebuf,0x0,fileLen+1);
fread(filebuf,fileLen,1,fp);
fclose(fp);

memset(password,0x0,sizeof(password));
printf("input %s password:",argv[1]);
scanf("%s",password);

if (strlen(password) == 0)
	exit(-1);

_getKeyData(filebuf,password,argv[2]);
util_free((void*)&filebuf);

return 0;
}
