#ifndef __CODEUTIL_H
#define __CODEUTIL_H

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define LOOP 2

/* 大写字母在密码串的比例 */
#ifndef UPPER
#define UPPER_RATIO 20
#endif


/*
参数1：待加密字符串
参数2：密码长度
参数3：特殊字符串是否指定 为空没有指定
参数4：加密后的字符串
参数5：参数4的长度
密码首字母不会是数字和特殊字符
*/

char* codeutil_password(const char* ,const char*,const char* ,char* ,size_t );
#endif
