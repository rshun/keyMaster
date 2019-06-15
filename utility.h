#ifndef __UTILITY_H
#define __UTILITY_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#ifndef uChar
#define uChar unsigned char
#endif

#ifndef uInt
#define uInt unsigned int
#endif

size_t utility_strlen(const char* );
char* utility_sha384(const char*,char*);
char* utility_sha512(const char*,char*);
char* utility_invert(const char*,char*,size_t );
uInt utility_chtonum(char );
char utility_trandigit(char );
char utility_galpha(uInt );
uInt utility_gdigit(const char* );
uInt utility_sumchar(const char* );
char* utility_tolower(char* );
char* utility_toupper(char* );
#endif