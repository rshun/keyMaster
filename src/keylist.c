/*
功能: 增删改查密码配置
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utility.h"
#include "keypub.h"
#include "list.h"

/*
显示所有节点
*/
static void dspKeyinfo(keyinfoPtr value,int* serial)
{
fprintf(stderr,"序号=%d\n",*serial);
fprintf(stderr,"中文名称:%s\n",value->cnName);
fprintf(stderr,"英文名称:%s\n",value->enName);
fprintf(stderr,"网址:%s\n",value->webAddr);
if (value->userID != NULL)
	fprintf(stderr,"用户名:%s\n",value->userID);
else
	fprintf(stderr,"用户名:\n");

fprintf(stderr,"密码长度:%s\n",value->keyLen);
if (value->updateTime != NULL)
	fprintf(stderr,"更新次数:%s\n",value->updateTime);
else
	fprintf(stderr,"更新次数:\n");

if (value->keyType != NULL)
	fprintf(stderr,"密钥类型:%s\n",value->keyType);
else
	fprintf(stderr,"密钥类型:\n");

if (value->allowSpec != NULL)
	fprintf(stderr,"允许指定特殊字符:%s\n",value->allowSpec);
else
	fprintf(stderr,"允许指定特殊字符:\n");

//fprintf(stderr,"位置:%d\n",value->which);
fprintf(stderr,"-----------------------------------------------\n");
}

static void _printhelp(const char* s)
{
    fprintf(stderr,"\nusage: %s -r username [-l keyword] [-u keyword] [-a filename] [-d keyword] [-m] [-t 0,1]\n",s);
    fprintf(stderr,"    -r <username> 用户名\n");
    fprintf(stderr,"    -l [keyword] 显示用户配置\n");
    fprintf(stderr,"    -a [filename] 新增配置\n");	
    fprintf(stderr,"    -u keyword 更新指定配置密码次数\n");
	fprintf(stderr,"    -d keyword 删除指定配置\n");
	fprintf(stderr,"    -m 修改密码\n");
	fprintf(stderr,"    -t 将配置文件改为[0-不加密,其余-加密]\n");
}

/*
功能: 加密数据并保存文件
参数1: 向量
参数2: 密钥
参数3: 明文
参数4: 密文文件
*/
static int write_encryfile(const char* iv,const char* key,const char* plaintxt,const char* filename)
{
char* ciphertext = NULL;
size_t cipherlen = 32 * 2 * (strlen(plaintxt) / 32 + 1);  
FILE *fp;
int ret;
char newfile[255];

if ((ciphertext = (char*)malloc(cipherlen)) == NULL)
	return -1;

memset(ciphertext,0x0,cipherlen);
ret = encrypt_aes256_cbc(key,plaintxt,iv,ciphertext,cipherlen);
if (ret <= 0)
{
	fprintf(stderr,"加密错误\n");
}
else
{
	memset(newfile,0x0,sizeof(newfile));
	snprintf(newfile,sizeof(newfile),"%s.new",filename);
    if ((fp = fopen(newfile,"wb")) == NULL)
	{
		fprintf(stderr,"open [%s] error,[%s]\n",newfile,strerror(errno));
		util_free((void*)&ciphertext);
		return -1;
	}
	fwrite(ciphertext,ret,1,fp);
	fclose(fp);
	if (access(filename,F_OK) == 0)
		remove(filename);

	rename(newfile,filename);
}

util_free((void*)&ciphertext);
return ret;
}

/*
显示密码配置
参数1: 密文文件
参数2: 向量
参数3: 密钥
参数4: 关键字
*/
static int _printconf(const char* filename,const char* iv,const char* key,const char* keyword)
{
int ret;
char* plaintxt = NULL;
LinkedList keyList;
ret = decode_encfile(filename,iv,key,&plaintxt);
if (ret < 0)
{
	printf("解密失败,ret%d\n",ret);
}
else
{
	if ((keyword == NULL) || (strlen(keyword) == 0))
	{
		printf("<%s>\n",plaintxt);
	}
	else
	{
		initList(&keyList);
		if (addlist4match(plaintxt,keyword,&keyList) > 0)
			processNode(&keyList,(PROCESS) dspKeyinfo);

		destoryList(&keyList,destoryKey);
	}
}

util_free((void*)&plaintxt);

return ret;
}

/*
功能: 新增密码配置
参数1: 密文文件
参数2: 向量
参数3: 密钥
参数4: 配置文件
*/
static int _addconf(const char* filename,const char* iv,const char* key,const char* conffile)
{
int plainlen =  1024;
char* plaintxt = NULL;
FILE *fp;
int flag=0;

if (access(filename,F_OK) == 0)
{
	plainlen = decode_encfile(filename,iv,key,&plaintxt);
	if (plainlen == -2)
	{
		util_free((void*)&plaintxt);
		return -1;
	}
	else if (plainlen == -1)
	{
		printf("解密失败.....\n");
		return -1;
	}
	flag=1;
}

if ((fp = fopen(conffile,"rb")) == NULL)
{
	printf("open [%s] is error,[%s]\n",conffile,strerror(errno));
	util_free((void*)&plaintxt);
	return -1;
}

plainlen *= 2;

if ((plaintxt = (char*)realloc(plaintxt,plainlen)) == NULL)
{
	util_free((void*)&plaintxt);
	fclose(fp);
	return -1;	
}
addnewconf(fp,plaintxt,plainlen,flag);
fclose(fp);

write_encryfile(iv,key,plaintxt,filename);

util_free((void*)&plaintxt);
return 0;
}

/*
功能: 删除配置中指定的信息
参数1: 密文文件
参数2: 向量
参数3: 密钥
参数4: 关键字
*/
static int _delconf(const char* filename,const char* iv,const char* key,const char* keyword)
{
LinkedList keyList;
char* plaintxt = NULL;
int ret,num,serial=0;
char confim[1+1];

ret = decode_encfile(filename,iv,key,&plaintxt);
if (ret < 0)
{
	printf("解密失败\n");
	util_free((void*)&plaintxt);
	return -1;
}

initList(&keyList);
num = addlist4match(plaintxt,keyword,&keyList);
if (num == 0)
{
	fprintf(stderr,"无匹配数据\n");
}
else if (num < 0)
{
	fprintf(stderr,"\n");
}
else
{
	processNode(&keyList,(PROCESS) dspKeyinfo);
	if (num > 1)
	{
		printf("input serial:");
		scanf("%d",&serial);
		if (deleteMatchNode(&keyList,plaintxt,serial) == 0)
			write_encryfile(iv,key,plaintxt,filename);		
	}
	else
	{
		printf("confim[Y/N]:");
		scanf("%s",confim);
		if ((confim[0] == 'Y') || (confim[0] == 'y'))
		{
			if (deleteMatchNode(&keyList,plaintxt,serial) == 0)
				write_encryfile(iv,key,plaintxt,filename);
		}
	}
}

destoryList(&keyList,destoryKey);

util_free((void*)&plaintxt);
return 0;
}

/*
功能: 更新配置文件指定更新次数,更新次数=原更新次数+1
参数1: 密文文件
参数2: 向量
参数3: 密钥
参数4: 关键字
*/
static int _updateconf(const char* filename,const char* iv,const char* key,const char* keyword)
{
LinkedList keyList;
char* plaintxt = NULL;
int ret,num,serial=0;
char confim[1+1];

ret = decode_encfile(filename,iv,key,&plaintxt);
if (ret < 0)
{
	printf("解密失败\n");
	util_free((void*)&plaintxt);
	return -1;
}

initList(&keyList);
num = addlist4match(plaintxt,keyword,&keyList);
if (num == 0)
{
	fprintf(stderr,"无匹配数据\n");
}
else if (num < 0)
{
	fprintf(stderr,"\n");
}
else
{
	processNode(&keyList,(PROCESS) dspKeyinfo);
	if (num > 1)
	{
		printf("input serial:");
		scanf("%d",&serial);
		if (updateNode(&keyList,plaintxt,serial) == 0)
			write_encryfile(iv,key,plaintxt,filename);
	}
	else
	{
		printf("confim[Y/N]:");
		scanf("%s",confim);
		if ((confim[0] == 'Y') || (confim[0] == 'y'))
		{
			if (updateNode(&keyList,plaintxt,serial) == 0)
				write_encryfile(iv,key,plaintxt,filename);
		}
	}
}

destoryList(&keyList,destoryKey);

util_free((void*)&plaintxt);
return 0;
}

/*
功能: 修改密码
参数1: 密文文件
参数2: 向量
参数3: 密钥
*/
static int _modifypassword(const char* filename,const char* iv,const char* key)
{
char* plaintxt = NULL;
int ret;
char password[100];

ret = decode_encfile(filename,iv,key,&plaintxt);
if (ret < 0)
{
	printf("解密失败\n");
	util_free((void*)&plaintxt);
	return -1;
}

memset(password,0x0,sizeof(password));
printf("input new password:",password);
scanf("%s",password);

write_encryfile(iv,password,plaintxt,filename);

util_free((void*)&plaintxt);

return 0;
}

/*
功能: 将明文转加密
参数1: 明文文件
参数2: 向量
参数3: 密钥
*/
static int plain2cipher(const char* filename,const char* iv,const char* key)
{
char* plaintxt = NULL;

if (getfilebuf(filename,&plaintxt) < 0)
	return -1;

write_encryfile(iv,key,plaintxt,filename);
updateEncflag(iv,"Y");

util_free((void*)&plaintxt);
return 0;
}

/*
功能: 将密文转成明文
参数1: 密文文件
参数2: 向量
参数3: 密钥
*/
static int cipher2plain(const char* filename,const char* iv,const char* key)
{
char* plaintxt = NULL;
int ret;
char newfile[255];
FILE *fp;

ret = decode_encfile(filename,iv,key,&plaintxt);
if (ret < 0)
{
	fprintf(stderr,"解密失败\n");
	util_free((void*)&plaintxt);
	return -1;
}

memset(newfile,0x0,sizeof(newfile));
snprintf(newfile,sizeof(newfile),"%s.new",filename);

if ((fp = fopen(newfile,"wb")) == NULL)
{
	fprintf(stderr,"open [%s] is error,[%s]\n",newfile,strerror(errno));
	util_free((void*)&plaintxt);
	return -1;
}
fwrite(plaintxt,ret,1,fp);
fclose(fp);

if (access(filename,F_OK) == 0)
	remove(filename);

rename(newfile,filename);

updateEncflag(iv,"N");

util_free((void*)&plaintxt);
return 0;
}

int main(int argc,char* argv[])
{
char* filename=NULL;
char username[255],password[100],keyword[100],userfile[255];
char newfile[255];
char flag[1+1]={0};
char encflag[1+1]={0};
int opt=0;
int isencflag=0;

if (argc < 2)
{
    _printhelp(argv[0]);
    exit(-1);
}

memset(username,0x0,sizeof(username));
memset(keyword,0x0,sizeof(keyword));
memset(userfile,0x0,sizeof(userfile));
memset(newfile,0x0,sizeof(newfile));

while ((opt = getopt(argc,argv,"r:u:t:d:lam")) != -1)
{
    switch (opt)
    {
		case 't':
			flag[0] = opt;
			snprintf(encflag,sizeof(encflag),"%s",optarg);
			break;
		case 'm':
			flag[0] = opt;
			break;
        case 'r':
            snprintf(username,sizeof(username),"%s",optarg);
            break;
		case 'a':
			flag[0] = opt;
			if (argv[optind] != NULL)
				snprintf(userfile,sizeof(userfile),"%s",argv[optind]);
			break;
		case 'l':
			flag[0] = opt;
			if (argv[optind] != NULL)
				snprintf(keyword,sizeof(keyword),"%s",argv[optind]);
			break;
    	case 'u':case 'd':
			flag[0] = opt;
			snprintf(keyword,sizeof(keyword),"%s",optarg);
            break;
        default:
            _printhelp(argv[0]);
            exit(-1);
    }
}

if (strlen(username) == 0)
{
	_printhelp(argv[0]);
	exit(-1);
}

if (strlen(flag) == 0)
{
	_printhelp(argv[0]);
	exit(-1);
}

/*解析文件,判断该用户是否加密,若加密则读取加密内容*/
isencflag = parseUser(username,&filename);
switch (isencflag)
{
	case -3:
		printf("[%s]file is not exists\n",argv[1]);
		util_free((void*)&filename);
		exit(-1);
	case -2:case -1:
		if (flag[0] == 'a')	/* 新用户 */
		{
			printf("input filename:");
			scanf("%s",newfile);

			if (addnewuser(isencflag,username,newfile) == 0)
			{
				printf("input %s new password:",username);
				scanf("%s",password);

				_addconf(newfile,username,password,userfile);
			}	
			exit(0);
		}
		else
		{
			printf("[%s]file is not exists\n",argv[1]);
			util_free((void*)&filename);
			exit(-1);
		}
		break;	
	default:
		break;
}

memset(password,0x0,sizeof(password));

if (flag[0] == 't')
{
	/* 不加密变成加密*/
	if ((encflag[0] != '0') && (isencflag == 0))
	{
		printf("input %s password:",username);
		scanf("%s",password);

		plain2cipher(filename,username,password);
	}
	else if ((encflag[0] == '0') && (isencflag == 1))
	{
		printf("input %s password:",username);
		scanf("%s",password);
		cipher2plain(filename,username,password);
	}
	else
	{
		if (isencflag == 0)
			printf("该用户配置文件不加密\n");
		else
			printf("该用户配置文件已加密\n");
	}
	util_free((void*)&filename);
	exit(0);
}

if (isencflag == 0)
{
	printf("该用户配置文件不加密\n");
	util_free((void*)&filename);
	exit(-1);
}

printf("input %s password:",username);
scanf("%s",password);

switch(flag[0])
{
	case 'l':
		_printconf(filename,username,password,keyword);
		break;
	case 'd':
		_delconf(filename,username,password,keyword);
		break;
	case 'a':
		_addconf(filename,username,password,userfile);
		break;
	case 'u':
		_updateconf(filename,username,password,keyword);
		break;
	case 'm':
		_modifypassword(filename,username,password);
		break;
}

util_free((void*)&filename);
exit(0);
}