#include "keypub.h"
#include "cJSON.h"
#include "utility.h"

const char* JSON_LABEL[]={"cnName","enName","webAddr","userID","keyLen","updateTime","keyType","allowSpec","webIcon"};

/*
功能: 读取文件内容并解密
参数1: 密文文件
参数2: 向量
参数3: 密钥
参数4: 明文
*/
int decode_encfile(const char* filename,const char* iv,const char* key,char** plaintxt)
{
int cipherlen,plainlen,ret;
char* ciphertxt = NULL;

if ((cipherlen = getfilebuf(filename,&ciphertxt)) < 0)
	return cipherlen;

plainlen = cipherlen;
if ((*plaintxt = (char*)malloc(plainlen)) == NULL)
{
	fprintf(stderr,"malloc is error,len=%d,[%s]\n",plainlen,strerror(errno));
	util_free((void*)&ciphertxt);
	return -1;
}

memset(*plaintxt,0x0,plainlen);

if ((ret = decrypt_aes256_cbc(key,ciphertxt,cipherlen,iv,*plaintxt,plainlen)) < 0)
{
	util_free((void*)&ciphertxt);
	return -2;
}

util_free((void*)&ciphertxt);
if (*plaintxt[0] == '[')
	return plainlen;
else
	return -2;
}

/* 
功能: 读取文件内容至filebuf
参数1: 文件名
参数2: filebuf

返回: 小于0,错误，其余返回文件长度
*/
off_t getfilebuf(const char* filename,char** filebuf)
{
off_t filelen;
FILE *fp;

if ((filelen = util_getfilesize(filename)) == 0)
{
	printf("[%s] is zero\n",filename);
	return -1;
}

if ((fp = fopen(filename,"rb")) == NULL)
{
	fprintf(stderr,"open [%s] is error,[%s]\n",filename,strerror(errno));
	return -1;
}

if ((*filebuf = (char*)malloc(filelen+1)) == NULL)
{
	fprintf(stderr,"malloc is error,len=[%zd],[%s]\n",filelen,strerror(errno));
	fclose(fp);
	return -1;
}

memset(*filebuf,0x0,filelen+1);
fread(*filebuf,filelen,1,fp);
fclose(fp);

return filelen;
}

/*
功能: 根据输入用户名，返回对应的用户文件
0-成功(不加密),1-成功(加密)
-1-配置文件中不存在该用户
-2-user.json文件不存在
-3-其他错误
*/
int parseUser(const char* userid,const char* filepath,char** configfile,char** userfile)
{
cJSON *root,*array;
char* buff = NULL;
int i,num,conffileLen,userfileLen;
char encflag[1+1]={0};

conffileLen = strlen(filepath)+strlen(CONFFILENAME)+3;
if ((*configfile = (char*)malloc(conffileLen)) == NULL)
{
	fprintf(stderr,"malloc configfile is error,%d,[%s]\n",conffileLen,strerror(errno));
	return -3;
}

memset(*configfile,0x0,conffileLen);
#ifdef LINUX
snprintf(*configfile,conffileLen,"%s/%s",filepath,CONFFILENAME);
#elif WIN32
snprintf(*configfile,conffileLen,"%s\\%s",filepath,CONFFILENAME);
#endif

if (getfilebuf(*configfile,&buff) < 0)
	return -2;

if ((root = cJSON_Parse(buff)) == NULL)
{
	printf("root error [%s]\n",cJSON_GetErrorPtr());
	util_free((void*)&buff);
	return -3;
}

num = cJSON_GetArraySize(root);
for(i=0;i<num;i++)
{
	if ((array = cJSON_GetArrayItem(root,i)) == NULL)
	{
		printf("array error [%s]\n",cJSON_GetErrorPtr());
		cJSON_Delete(root);
		util_free((void*)&buff);
		return -3;
	}

	if (strncasecmp(cJSON_GetStringValue(cJSON_GetObjectItem(array,"userID")),userid,strlen(userid)) == 0)
	{
		userfileLen = strlen(filepath) + strlen(cJSON_GetStringValue(cJSON_GetObjectItem(array,"filename"))) + 3;
		if ((*userfile = (char*)malloc(userfileLen)) == NULL)
		{
			fprintf(stderr,"malloc configfile is error,%d,[%s]\n",userfileLen,strerror(errno));
			cJSON_Delete(root);
			util_free((void*)&buff);
			return -3;
		}
		memset(*userfile,0x0,userfileLen);
		#ifdef LINUX
			snprintf(*userfile,userfileLen,"%s/%s",filepath,cJSON_GetStringValue(cJSON_GetObjectItem(array,"filename")));
		#elif WIN32
			snprintf(*userfile,userfileLen,"%s\\%s",filepath,cJSON_GetStringValue(cJSON_GetObjectItem(array,"filename")));
		#endif
		//util_put2Value(cJSON_GetStringValue(cJSON_GetObjectItem(array,"filename")),userfile);
        if (cJSON_GetStringValue(cJSON_GetObjectItem(array,"isEncrypt")) != NULL)
		{
			snprintf(encflag,sizeof(encflag),"%s",cJSON_GetStringValue(cJSON_GetObjectItem(array,"isEncrypt")));
		}
		cJSON_Delete(root);
		util_free((void*)&buff);
		if ((encflag[0] == 'y') || (encflag[0] == 'Y'))
			return 1;
		else
			return 0;
	}
}

cJSON_Delete(root);
util_free((void*)&buff);
return -1;
}

int updateEncflag(const char* userid,const char* encflag,const char* conffile)
{
char newfile[255];
cJSON *root,*array;
char* buff;
int i,num;
off_t filelen;
FILE *fp;

memset(newfile,0x0,sizeof(newfile));
snprintf(newfile,sizeof(newfile),"%s.new",conffile);

if ((filelen = getfilebuf(conffile,&buff)) < 0)
	return -1;

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
		cJSON_ReplaceItemInObject(cJSON_GetArrayItem(root,i),"isEncrypt",cJSON_CreateString(encflag));
		if ((fp = fopen(newfile,"wb")) != NULL)
		{
			fwrite(cJSON_Print(root),strlen(cJSON_Print(root)),1,fp);
			fclose(fp);
			if (rename(newfile,conffile) < 0 )
			{
				if (errno == EEXIST)
					remove(conffile);
			}
			rename(newfile,conffile);
		}

		cJSON_Delete(root);
		util_free((void*)&buff);
		if ((encflag[0] == 'y') || (encflag[0] == 'Y'))
			return 1;
		else
			return 0;
	}
}

cJSON_Delete(root);
util_free((void*)&buff);
return -1;
}

void destoryKey(void** p)
{
keyinfoPtr* value = (keyinfoPtr*)p;

	util_free((void**)&(*value)->cnName);
	util_free((void**)&(*value)->enName);
	util_free((void**)&(*value)->webAddr);
	util_free((void**)&(*value)->userID);
	util_free((void**)&(*value)->keyLen);
	util_free((void**)&(*value)->updateTime);
	util_free((void**)&(*value)->keyType);
	util_free((void**)&(*value)->allowSpec);
}

/*
功能:匹配关键字(不区分大小写)
根据输入值，在中文名称和网址中匹配是否存在,存在返回1,不存在返回0
 */
int compValue(keyinfoPtr ptrJson,const char* keyWord)
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
char* initKeylen(char** value)
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

/*
校验密码生成次数,如果为空赋默认值
*/
char* initTimes(char** value)
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
功能: 将匹配的json对象放进list
*/
int addlist4match(const char* jsonbuf,const char* keyword,LinkedListPtr keylist)
{
cJSON *root,*array,*value;
keyinfoPtr ptrJson;
int i,j,num,count=0;
int labelLen=sizeof(JSON_LABEL)/sizeof(JSON_LABEL[0]);

if ((root = cJSON_Parse(jsonbuf)) == NULL)
{
	printf("root error [%s]\n",cJSON_GetErrorPtr());
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

	if ((ptrJson = (keyinfoPtr)malloc(sizeof(keyinfo))) == NULL)
	{
		printf("malloc is error,[%s]\n",strerror(errno));
		cJSON_Delete(root);
		return -1;
	}

  	for(j=0;j<labelLen;j++)
	{
 		value = cJSON_GetObjectItem(array,JSON_LABEL[j]);
		if (value == NULL)
			continue;

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
	ptrJson->which = i;
	if (compValue(ptrJson,keyword) > 0)
	{
		appendNode(keylist,ptrJson);
		count++;
	}
	//deallocate(ptrJson);
}
//util_free((void**)ptrJson);

cJSON_Delete(root);
return count;
}

/*
功能: 在list中删除指定的json对象
*/
int deleteMatchNode(LinkedListPtr keylist,char* jsonbuf,int which)
{
cJSON *root;
int count=0,match=-1;
NodePtr current = keylist->head;
keyinfoPtr ptrJson;

while (current != NULL)
{
	ptrJson = current->data;
	if (count == which)
	{
		match = ptrJson->which;
		break;
	}
	count++;
    current = current->next;
}

if (match < 0)
{
	fprintf(stderr,"未找到匹配的序号\n");
	return -1;
}

if ((root = cJSON_Parse(jsonbuf)) == NULL)
{
	fprintf(stderr,"root error [%s]\n",cJSON_GetErrorPtr());
	return -1;
}

cJSON_DeleteItemFromArray(root,match);
strcpy(jsonbuf,cJSON_Print(root));

cJSON_Delete(root);
return 0;
}

/*
功能: 更新json对象中updatetime
*/
int updateNode(LinkedListPtr keylist,char* jsonbuf,int which,const char* type,const char* newvalue)
{
cJSON *root,*value;
int count=0,match=-1;
NodePtr current = keylist->head;
keyinfoPtr ptrJson;
char cUpdatetime[5+1];

while (current != NULL)
{
	ptrJson = current->data;
	if (count == which)
	{
		match = ptrJson->which;
		break;
	}
	count++;
    current = current->next;
}

if (match < 0)
{
	fprintf(stderr,"未找到匹配的序号\n");
	return -1;
}

if ((root = cJSON_Parse(jsonbuf)) == NULL)
{
	fprintf(stderr,"root error [%s]\n",cJSON_GetErrorPtr());
	return -1;
}

//更新updatetimes
if (strncmp(type,"updateTime",strlen("updateTime")) == 0)
{
	value = cJSON_GetObjectItem(cJSON_GetArrayItem(root,match),"updateTime");

	memset(cUpdatetime,0x0,sizeof(cUpdatetime));
	snprintf(cUpdatetime,sizeof(cUpdatetime),"%d",atoi(cJSON_GetStringValue(value)) + 1);

	cJSON_ReplaceItemInObject(cJSON_GetArrayItem(root,match),"updateTime",cJSON_CreateString(cUpdatetime));
}
else
{
	if (cJSON_GetObjectItem(cJSON_GetArrayItem(root,match),type) != NULL)
		cJSON_ReplaceItemInObject(cJSON_GetArrayItem(root,match),type,cJSON_CreateString(newvalue));
	else
		cJSON_AddItemReferenceToObject(cJSON_GetArrayItem(root,match),type,cJSON_CreateString(newvalue));
}

strcpy(jsonbuf,cJSON_Print(root));

cJSON_Delete(root);
return 0;
}

/*
功能: 在user.json新增用户及相关信息
参数1: 标志（-2，新增user.json文件，并新增用户,-1新增用户
参数2: 用户名
参数3: 用户配置文件 (带路径)
参数4: 用户文件名
*/
int addnewuser(int flag,const char* userid,const char* userconffile,const char* userfile)
{
FILE *fp;
cJSON *root,*newobj;
char* buff;

if (flag == -2)	/*第一次添加用户*/
{
	root = cJSON_CreateArray();
	newobj = cJSON_CreateObject();

	cJSON_AddStringToObject(newobj, "userID", userid);
	cJSON_AddStringToObject(newobj, "filename", userfile);
	cJSON_AddStringToObject(newobj, "isEncrypt", "Y");
	cJSON_AddItemReferenceToArray(root,newobj);
}
else	/* 新增用户 */
{
	if (getfilebuf(userconffile,&buff) < 0)
		return -1;

	if ((root = cJSON_Parse(buff)) == NULL)
	{
		printf("root error [%s]\n",cJSON_GetErrorPtr());
		util_free((void*)&buff);
		return -3;
	}
	util_free((void*)&buff);

	newobj = cJSON_CreateObject();
	cJSON_AddStringToObject(newobj, "userID", userid);
	cJSON_AddStringToObject(newobj, "filename", userfile);
	cJSON_AddStringToObject(newobj, "isEncrypt", "Y");
	
	cJSON_AddItemReferenceToArray(root,newobj);
}

if ((fp = fopen(userconffile,"wb")) == NULL)
{
	fprintf(stderr,"open [%s] is error,[%s]\n",userconffile,strerror(errno));
	cJSON_Delete(root);
	return -1;
}

fwrite(cJSON_Print(root),strlen(cJSON_Print(root)),1,fp);
fclose(fp);

cJSON_Delete(root);
return 0;
}

/*
功能: 读取自定义配置文件内容添加到json
参数1: 自定义配置文件流
参数2: 原密码配置明文
参数3: 明文长度
参数4: 标志,1-在原配置中追加, 0-新增配置

返回: 0成功, 其余-失败
*/
int addnewconf(const char* conffilename,char* filebuf,size_t filelen,int flag)
{
cJSON *root,*new;
FILE *fp;
char buff[1024],name[1024],value[1024];
int labelLen=sizeof(JSON_LABEL)/sizeof(JSON_LABEL[0]);
int islabel[labelLen];

if ((fp = fopen(conffilename,"rb")) == NULL)
{
	fprintf(stderr,"open [%s] is error,[%s]\n",conffilename,strerror(errno));
	return -1;
}

new = cJSON_CreateObject();
memset(&islabel,0,sizeof(islabel));

while (!feof(fp))
{
	memset(buff,0x0,sizeof(buff));
	fgets(buff,sizeof(buff),fp);

	if (strstr(buff,"allowSpec=") == NULL)
		buff[strcspn(buff,"#")] = '\0';

	util_trim(buff);
	if (strlen(buff) == 0) continue;

	memset(name,0x0,sizeof(name));
	memset(value,0x0,sizeof(value));
	util_splitbuff(buff,name,sizeof(name),value,sizeof(value));

	util_trim(value);

	for(int i=0;i<labelLen;i++)
	{
		if ((strncmp(name,JSON_LABEL[i],strlen(name)) == 0) && (strlen(value) > 0))
		{
			islabel[i]=1;
			cJSON_AddStringToObject(new, JSON_LABEL[i], value);
		}
	}
}
fclose(fp);

for(int i=0;i<labelLen;i++)
{
	if (islabel[i] == 0)
	{
		if (i>=1 && i<=2)
		{
			fprintf(stderr,"[%s] is must input\n",JSON_LABEL[i]);
			return -1;
		}
		cJSON_AddStringToObject(new, JSON_LABEL[i], "");
	}
}

if (flag == 1)
{
	if ((root = cJSON_Parse(filebuf)) == NULL)
	{
		printf("root error [%s]\n",cJSON_GetErrorPtr());
		return -1;
	}
}
else
{
	root = cJSON_CreateArray();
}
cJSON_AddItemReferenceToArray(root,new);

if (cJSON_PrintPreallocated(root,filebuf,filelen,1) == 0)
{
	fprintf(stderr,"bufflen is ineffinecy\n");
}
else
{
	memset(filebuf,0x0,filelen);
	snprintf(filebuf,filelen,"%s",cJSON_Print(root));
}

cJSON_Delete(root);
return 0;
}
