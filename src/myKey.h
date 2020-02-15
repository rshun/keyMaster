#ifndef __MYKEY_H
#define __MYKEY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef DEFAULT_PWDLEN
#define DEFAULT_PWDLEN "6211"
#endif 

#ifndef uInt
#define uInt unsigned int
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
}keyinfo,*keyinfoPtr;


#endif