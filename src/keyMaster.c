#include "keyMaster.h"
#include "cJSON.h"
#include "codeutil.h"
#include "utility.h"
#include "keypub.h"

/*	只保留域名地址,去掉二级域名
参数: https://www.google.com/
返回: google.com
*/
const char HTTP_HEAD[]="http://";
const char HTTPS_HEAD[]="https://";
const char WWW_ADDR[]="www.";
const char BBS_ADDR[]="bbs.";
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

static int _getKeyData(const char* jsonbuf,const char* primary,const char* keyword)
{
const char* JSON_LABEL[]={"cnName","enName","webAddr","userID","keyLen","updateTime","keyType","allowSpec","webIcon"};	
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
				initKeylen(&ptrJson->keyLen);
				break;
			case 5:
				util_put2Value(cJSON_GetStringValue(value),&ptrJson->updateTime);
				initTimes(&ptrJson->updateTime);
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
			clearscreen();
			printf("[%s]\t[%s]\tuser=[ %s ]\tpassword=[ %s ]\n",ptrJson->enName,ptrJson->cnName,ptrJson->userID,password);
			
			util_free((void*)&password);
			util_free((void*)&code);
			util_free((void*)&addr);
		}
	}
	destoryKey((void*)&ptrJson);
}
util_free((void**)ptrJson);

cJSON_Delete(root);
return 0;
}

int main(int argc,char* argv[])
{
FILE *fp;
char password[100],key[100];
char *filebuf=NULL;
char *filename=NULL;
char *conffile=NULL;
char filepath[255];		/* 配置文件路径 */
off_t fileLen;
int ret;

if (argc < 3)
{
	printf("usage:%s user keyword [configure path]\n",argv[0]);
	exit(-1);
}

memset(filepath,0x0,sizeof(filepath));
if (argc > 3)
	snprintf(filepath,sizeof(filepath),"%s",argv[3]);
else
	snprintf(filepath,sizeof(filepath),"./");

ret = parseUser(argv[1],filepath,&conffile,&filename);
if (ret < 0)
{
	printf("[%s]file is not exists\n",argv[1]);
	util_free((void*)&filename);
	util_free((void*)&conffile);
	exit(EXIT_FAILURE);
}
util_free((void*)&conffile);
if (ret == 1)
{
	memset(key,0x0,sizeof(key));
	printf("input %s config file password:",argv[1]);
	scanf("%s",key);

	if (decode_encfile(filename,argv[1],key,&filebuf) < 0)
	{	
		util_free((void*)&filename);
		util_free((void*)&filebuf);
		fprintf(stderr,"配置文件密码错误ret=%d\n",ret);
		exit(-1);
	}
}
else
{
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

	memset(filebuf,0x0,fileLen+1);
	fread(filebuf,fileLen,1,fp);
	fclose(fp);
}
util_free((void*)&filename);

memset(password,0x0,sizeof(password));
printf("input %s password:",argv[1]);
scanf("%s",password);

if (strlen(password) == 0)
	exit(-1);

_getKeyData(filebuf,password,argv[2]);
util_free((void*)&filebuf);

return 0;
}
