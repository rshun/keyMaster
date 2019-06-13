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
char* cnName;
char* enName;
char* webAddr;
char* userID;
char* keyLen;
char* updateTime;
char* keyType;
char* allowSpec;
char* webIcon;	
}keyinfo,*keyinfoPtr;


#endif
