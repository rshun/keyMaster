/*
功能: 增删改查密码配置
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
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
size_t cipherlen = 32 * 2 * (strlen(plaintxt) / 32 + 1);  //32是AES256的LEN
FILE *fp;
int ret;
char newfile[255];

if ((ciphertext = (char*)malloc(cipherlen)) == NULL)
{
	fprintf(stderr,"ciphertxt malloc error,%d,[%s]\n",cipherlen,strerror(errno));
	return -1;
}

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
功能: 将明文转加密
参数1: 用户明文文件
参数2: 向量
参数3: 密钥
参数4: 配置文件
*/
static int plain2cipher(const char* filename,const char* iv,const char* key,const char* conffile)
{
char* plaintxt = NULL;

if (getfilebuf(filename,&plaintxt) < 0)
	return -1;

write_encryfile(iv,key,plaintxt,filename);
updateEncflag(iv,"Y",conffile);

util_free((void*)&plaintxt);
return 0;
}

/*
功能: 将密文转成明文
参数1: 密文文件
参数2: 向量
参数3: 密钥
*/
static int cipher2plain(const char* filename,const char* iv,const char* key,const char* conffile)
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
fwrite(plaintxt,strlen(plaintxt),1,fp);
fclose(fp);

if (access(filename,F_OK) == 0)
	remove(filename);

rename(newfile,filename);

updateEncflag(iv,"N",conffile);

util_free((void*)&plaintxt);
return 0;
}

/*
显示密码配置
参数1: 明文
参数2: 关键字
*/
static void _printconf(const char* plaintxt,const char* keyword)
{
LinkedList keyList;

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

/*
功能: 删除配置中指定的信息
参数1: 明文
参数2: 关键字

返回: 1-成功,0--无匹配数据
*/
static int _delconf(char* plaintxt,const char* keyword)
{
LinkedList keyList;
int num,serial=0;
char confim[1+1];

initList(&keyList);
num = addlist4match(plaintxt,keyword,&keyList);
if (num == 0)
{
	fprintf(stderr,"无匹配数据,<%s>\n",keyword);
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
		{
			destoryList(&keyList,destoryKey);
			return 1;
		}
	}
	else
	{
		printf("confim[Y/N]:");
		scanf("%s",confim);
		if ((confim[0] == 'Y') || (confim[0] == 'y'))
		{
			if (deleteMatchNode(&keyList,plaintxt,serial) == 0)
			{
				destoryList(&keyList,destoryKey);
				return 1;
			}
		}
	}
}

destoryList(&keyList,destoryKey);

return 0;
}

/*
功能: 更新配置文件指定更新配置
参数1: 明文
参数2: 关键字
参数3: 配置类型
参数4: value

返回: -1--错误, 0--无匹配数据,1--更新成功
*/
static int _updateconf(char* plaintxt,const char* keyword,const char* type,const char* newvalue)
{
LinkedList keyList;
int num,serial=0;
char confim[1+1];
char label[20];

memset(label,0x0,sizeof(label));
switch (type[0])
{
	case 's':case 'S':
		snprintf(label,sizeof(label),"userID");
		break;
	case 'u':case 'U':
		snprintf(label,sizeof(label),"updateTime");
		break;
	case 'k':case 'K':
		snprintf(label,sizeof(label),"keyLen");
		break;
	case 'T':case 't':
		snprintf(label,sizeof(label),"keyType");
		break;
	case 'a':case 'A':
		snprintf(label,sizeof(label),"allowSpec");
		break;
	case 'w':case 'W':
		snprintf(label,sizeof(label),"webIcon");
		break;
	default:
		fprintf(stderr,"参数有误\n");
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
		if (updateNode(&keyList,plaintxt,serial,label,newvalue) == 0)
		{
			destoryList(&keyList,destoryKey);
			return 1;
		}
	}
	else
	{
		printf("confim[Y/N]:");
		scanf("%s",confim);
		if ((confim[0] == 'Y') || (confim[0] == 'y'))
		{
			if (updateNode(&keyList,plaintxt,serial,label,newvalue) == 0)
			{
				destoryList(&keyList,destoryKey);
				return 1;
			}
		}
	}
}

destoryList(&keyList,destoryKey);
return 0;
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
int plainlen =  1024; //TODO 要重新计算
char* plaintxt = NULL;
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
		fprintf(stderr,"解密失败.....\n");
		return -1;
	}
	flag=1;
}

plainlen *= 2;

if ((plaintxt = (char*)realloc(plaintxt,plainlen)) == NULL)
{
	util_free((void*)&plaintxt);
	return -1;	
}

addnewconf(conffile,plaintxt,plainlen,flag);
write_encryfile(iv,key,plaintxt,filename);

util_free((void*)&plaintxt);
return 0;
}

static void _printhelp(const char* s)
{
    fprintf(stderr,"\nusage: %s -r username [-p user.json路径] [-l keyword] [-u keyword] [-g filename] [-a filename] [-d keyword] [-m] [-t 0,1]\n",s);
    fprintf(stderr,"    -r <username> 用户名\n");
	fprintf(stderr,"    -c [user.json路径],默认当前路径\n");
    fprintf(stderr,"    -l [keyword] 显示用户配置\n");
    fprintf(stderr,"    -a [filename] 新增配置\n");	
    fprintf(stderr,"    -u keyword [s-用户名,k-密码长度,u-密码次数,t-密钥类型,a-指定特殊字符,w-网站图标] [value] 更新指定配置\n");
	fprintf(stderr,"    -d keyword 删除指定配置\n");
	fprintf(stderr,"    -m 修改密码\n");
	fprintf(stderr,"    -t 将配置文件改为[0-不加密,其余-加密]\n");
	fprintf(stderr,"    -g filename 生成新增配置的模板文件\n");
}

/*
功能: 生成配置文件模板
参数1: 文件名
*/
static void _genconfile(const char* filename)
{
FILE *fp;

if ((fp = fopen(filename,"wb")) == NULL)
{
	fprintf(stderr,"open [%s] error,[%s]\n",filename,strerror(errno));
	return;
}

fprintf(fp,"#中文名称\ncnName=\n\n");
fprintf(fp,"#英文名称(必输)\nenName=\n\n");
fprintf(fp,"#网址(必输)\nwebAddr=\n\n");
fprintf(fp,"#用户名\nuserID=\n\n");
fprintf(fp,"#密码长度\n");
fprintf(fp,"# 长度为3 第1位是字母 第2位是数字 第3位是特殊字符 \n");
fprintf(fp,"# 长度为4 前2位是字母 第3位是数字 第4位是特殊字符\n");
fprintf(fp,"# 密码长度必须大于6,且必须包含字母或数字\n");
fprintf(fp,"# 大写字母占大于20%%\n");
fprintf(fp,"keyLen=\n\n");
fprintf(fp,"#更新次数\nupdateTime=\n\n");
fprintf(fp,"#密钥类型 适用于一个网站多个密码\nkeyType=\n\n");
fprintf(fp,"#只允许指定特殊字符\nallowSpec=\n\n");
fprintf(fp,"#网站图标\nwebIcon=\n\n");

fclose(fp);
}

int main(int argc,char* argv[])
{
int ch,mainflag=0,subflag=0,flag=0;
int ret = 0;
int isencflag=0;		/* 是否加密 */
char password[255];		/* 用户配置文件密码 */
char newkey[255];		/* 新密码 */
char username[100];
char filepath[255];		/* 配置文件路径 */
char userfile[255];
char keyword[100];		/* 关键字 */
char encflag[1+1]={0};	/* 加密标志 */
char conftype[1+1]={0};	/* 更新的项目 */
char newvalue[100];		/* 更新后的值 */
char* configfile=NULL;	/* 配置文件 */
char* filename=NULL;	/* 用户文件名 */
char* plaintxt = NULL;	/* 配置文件明文 */
const char* const short_options = "c:g:r:u:t:d:a:l::m";
const struct option long_options[] = {
	{"user",    required_argument, NULL, 'r'},
	{"conf",    required_argument, NULL, 'c'},
	{"add",     required_argument, NULL, 'a'},
	{"update",  required_argument, NULL, 'u'},
	{"del",     required_argument, NULL, 'd'},
	{"put",     required_argument, NULL, 'g'},
	{"to",      required_argument, NULL, 't'},

	{"list",    no_argument,       NULL, 'l'},
	{"mod",     no_argument,       NULL, 'm'},
	{0,         0,                 NULL,  0 }
	};

memset(username,0x0,sizeof(username));
memset(filepath,0x0,sizeof(filepath));
memset(userfile,0x0,sizeof(userfile));
memset(keyword,0x0,sizeof(keyword));
memset(newvalue,0x0,sizeof(newvalue));

while( (ch=getopt_long(argc, argv, short_options, long_options, NULL)) != -1 ) 
{
 	switch(ch)
	{
		case 'g':
			_genconfile(optarg);
			exit(0);
		case 't':
			snprintf(encflag,sizeof(encflag),"%s",optarg);
			flag=ch;
			subflag++;
			break;
		case 'r':
			snprintf(username,sizeof(username),"%s",optarg);
			mainflag++;
			break;
		case 'm':
			subflag++;
			break;
		case 'c':
			snprintf(filepath,sizeof(filepath),"%s",optarg);
			break;
		case 'a':
			snprintf(userfile,sizeof(userfile),"%s",optarg);
			subflag++;
			flag=ch;
			break;
		case 'l':
			if ((argv[optind] != NULL) && (argv[optind][0] != '-'))
				snprintf(keyword,sizeof(keyword),"%s",argv[optind]);
			flag=ch;
			subflag++;
			break;
    	case 'd':
			flag=ch;
			snprintf(keyword,sizeof(keyword),"%s",optarg);
			subflag++;
            break;			
		case 'u':
			flag=ch;
			snprintf(keyword,sizeof(keyword),"%s",optarg);
			while (optind < argc)
			{
				if ((argv[optind] == NULL) || (argv[optind][0] == '-'))
					break;
				
				snprintf(conftype,sizeof(conftype),"%s",argv[optind++]);
				snprintf(newvalue,sizeof(newvalue),"%s",argv[optind++]);
			}
			subflag++;
			break;
	}
}

/* 校验参数是否正确 */
if (!mainflag)
{
	_printhelp(argv[0]);
	exit(EXIT_FAILURE);
}

if (subflag != 1)
{
	_printhelp(argv[0]);
	exit(EXIT_FAILURE);
}

/* 配置文件若未指定默认当前路径 */
if (strlen(filepath) == 0)
	snprintf(filepath,sizeof(filepath),"./");

/*
解析文件,判断该用户是否加密,若加密则读取加密内容
如果指定路径,则判断当前路径下是否有用户文件,没有则到指定路径再找用户文件 
*/
isencflag = parseUser(username,filepath,&configfile,&filename);
if (isencflag == -3) 
{
	util_free((void*)&configfile);
	exit(EXIT_FAILURE);
}

/*
新增功能且用户文件不是加密状态
*/
if ((flag == 'a') && (isencflag != 0))
{
	if ((isencflag == -2) || (access(filename,F_OK) != 0))	/* user.json或用户配置文件不存在 */
	{
		if ((filename = (char*)malloc(strlen(username)+6)) == NULL)
		{
			fprintf(stderr,"filename malloc is error,%d,[%s]\n",strlen(username)+6,strerror(errno));
			util_free((void*)&configfile);
			exit(EXIT_FAILURE);
		}

		memset(filename,0x0,strlen(username)+6);
		snprintf(filename,strlen(username)+6,"%s.json",username);
	}

	ret = 0;
	if (isencflag < 0)	/* 新增user.json或在user.json新增用户 */
		ret = addnewuser(isencflag,username,configfile,filename);

	if (!ret)	/* 新增用户配置文件 */
	{
		printf("input %s new password:",username);
		scanf("%s",password);

		_addconf(filename,username,password,userfile);
	}

	util_free((void*)&filename);
	util_free((void*)&configfile);
	exit(EXIT_SUCCESS);	
}

if (access(filename,F_OK) != 0)
{
	fprintf(stderr,"用户配置文件不存在,[%s]\n",filename);
	util_free((void*)&filename);
	util_free((void*)&configfile);
	exit(EXIT_FAILURE);
}

memset(password,0x0,sizeof(password));
/* 加密转换 */
if (flag == 't')
{
	/* 不加密变成加密*/
	if ((encflag[0] != '0') && (isencflag == 0))
	{
		printf("input %s new password:",username);
		scanf("%s",password);

		plain2cipher(filename,username,password,configfile);
	}
	else if ((encflag[0] == '0') && (isencflag == 1))
	{
		printf("input %s password:",username);
		scanf("%s",password);
		cipher2plain(filename,username,password,configfile);
	}
	else
	{
		if (isencflag == 0)
			printf("该用户配置文件不加密\n");
		else
			printf("该用户配置文件已加密\n");
	}
	util_free((void*)&filename);
	util_free((void*)&configfile);
	exit(EXIT_SUCCESS);
}

if (isencflag != 1)
{
	fprintf(stderr,"user.json不存在,或%s.json不加密\n",username,username);
	util_free((void*)&filename);
	util_free((void*)&configfile);
	exit(EXIT_FAILURE);
}


printf("input %s password:",username);
scanf("%s",password);

if ((ret = decode_encfile(filename,username,password,&plaintxt)) < 0)
{
	fprintf(stderr,"解密失败\n");
	util_free((void*)&plaintxt);
	util_free((void*)&filename);
	util_free((void*)&configfile);
	exit(EXIT_FAILURE);
}

switch(flag)
{
	case 'l':
		_printconf(plaintxt,keyword);
		break;
	case 'd':
		if (_delconf(plaintxt,keyword))
			write_encryfile(username,password,plaintxt,filename);
		break;
	case 'u':
		if (_updateconf(plaintxt,keyword,conftype,newvalue))
		{
			write_encryfile(username,password,plaintxt,filename);
			_printconf(plaintxt,keyword);
		}
		break;
	case 'm':
		memset(newkey,0x0,sizeof(newkey));
		printf("input new password:");
		scanf("%s",newkey);
		write_encryfile(username,newkey,plaintxt,filename);
		break;
}

util_free((void*)&plaintxt);
util_free((void*)&filename);
util_free((void*)&configfile);

exit(EXIT_SUCCESS);
}