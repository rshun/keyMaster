#ifndef __KEYPUB_H
#define __KEYPUB_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "list.h"

#ifndef DEFAULT_PWDLEN
#define DEFAULT_PWDLEN "811"
#endif 

#ifndef uInt
#define uInt unsigned int
#endif

#ifndef CONFFILENAME
#define CONFFILENAME "user.json"
#endif

typedef struct
{
char* cnName;	/* 中文名称 */
char* enName;	/* 英文名称 */
char* webAddr;	/* 网址 */
char* userID;	/* 用户名 */
char* keyLen;	/* 密码长度		
				长度为3 第1位是字母 第2位是数字 第3位是特殊字符 
				长度为4 前2位是字母 第3位是数字 第4位是特殊字符
				密码长度必须大于6,且必须包含字母或数字
				除此之外 8位字母 1位数字 1位特殊字符
				大写字母占大于20%   */
char* updateTime;	/* 更新次数 */
char* keyType;		/* 密钥类型 适用于一个网站多个密码*/
char* allowSpec;	/* 只允许指定特殊字符 */
char* webIcon;		/* 网站图标 */
char* password;
int   which;
}keyinfo,*keyinfoPtr;

off_t getfilebuf(const char* ,char** );
int parseUser(const char* ,const char*,char**,char** );
int updateEncflag(const char* ,const char* ,const char*);
int addlist4match(const char* ,const char* ,LinkedListPtr );
int deleteMatchNode(LinkedListPtr, char* ,int );
int updateNode(LinkedListPtr, char* ,int ,const char*,const char*);
void destoryKey(void** );
int addnewuser(int ,const char* ,const char*,const char*);
int addnewconf(const char* ,char* ,size_t ,int);
int decode_encfile(const char* ,const char* ,const char* ,char** );
char* initTimes(char** );
char* initKeylen(char** );
int compValue(keyinfoPtr ,const char* );

#endif