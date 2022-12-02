#ifndef __util_H
#define __util_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

//AES 加密指定CBC模式 
#define CBC 1

#ifndef uChar
#define uChar unsigned char
#endif

#ifndef uInt
#define uInt unsigned int
#endif

size_t util_strlen(const char* );
char* util_sha384(const char*,char*);
char* util_sha512(const char*,char*,size_t len);
char* util_invert(const char*,char*,size_t );
uInt util_ch2num(char );
char util_num2spec(uInt );
char util_char2spec(char );
char util_galpha(uInt );
uInt util_gdigit(const char* );
uInt util_sumchar(const char* );
char* util_tolower(char* );
char* util_toupper(char* );
off_t util_getfilesize(const char* );
int util_isdigitstr(const char* );
void util_free(void** );
char* util_put2Value(char* ,char** );
uInt util_getKeyLen(const char* );
int util_initValue(char** ,size_t );
int util_base64enc(const char* ,int ,char* ,int );
int util_base64decode(const char* ,int ,char* ,int );
uChar* util_str2hex(const char* ,uChar* result,size_t );
char* util_trim(char* );
void util_splitbuff(const char* ,char* ,size_t ,char* ,size_t );
int util_isdomain(char* );

size_t pkcs7_padding_data_length( uint8_t * , size_t , uint8_t  );
int pkcs7_padding_valid( uint8_t *, size_t , size_t , uint8_t  );
int pkcs7_padding_pad_buffer( uint8_t *,  size_t , size_t , uint8_t  );

int encrypt_aes256_cbc(const char* ,const char* ,const char* ,char* ,size_t );
int decrypt_aes256_cbc(const char* ,const char* ,size_t ,const char*,char* ,size_t );
#endif
