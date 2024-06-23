#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>

enum {
	BUFFER = 4096,
	NONCE_SIZE = 8,
    NONCES = 8192,
	TIME_SIZE = 8,
	BLOCK_LENGHT = 64,
	SHA1_LENGHT = 20,
	CONST1 = 0x5c,
	CONST2 = 0X36,
	PORT = 9999,
	LOGIN_SIZE = 255,
	RESULT_SIZE = 7,
	KEY_CHAR_SIZE = 40,
};

typedef struct nonceDatabase {
	uint64_t nonce[NONCES];
	time_t timestamp[NONCES];
	unsigned int lenght;
} nonces;

void
init(struct sockaddr_in *sockaddress, int port, nonces *database, char *servIP){
    memset(sockaddress, 0, sizeof(*sockaddress));
	sockaddress->sin_family = AF_INET;
    sockaddress->sin_addr.s_addr = inet_addr(servIP);
	sockaddress->sin_port = htons(port);
    if(database != NULL){
        memset(database, 0, sizeof(nonces));
	    memset(database->nonce, 0, sizeof(uint64_t) * NONCES);
	    memset(database->timestamp, 0, sizeof(time_t) * NONCES);
	    database->lenght = 0;
    }
}

int
configTimeOut(int connfd)
{
	struct timeval timeout;

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	if (setsockopt(connfd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof timeout) < 0) {
        return 0;
	}
	if (setsockopt(connfd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		       sizeof timeout) < 0) {
        return 0;
	}
    return 1;
}

int
isHexStr(char *str)
{
	int valid = 1;

	for (; *str != '\0'; str++) {
		if ((*str < '0' || *str > '9') && (*str < 'a' || *str > 'f')) {
			valid = 0;
		}
	}
	return valid;
}

void
strToHex(unsigned char result[], char *str)
{
	int i, j;
	char hex[3];

	j = 0;
	memset(result, 0, sizeof(unsigned char) * (SHA1_LENGHT + 1));
	for (i = 1; i < strlen(str); i += 2) {
		memset(hex, 0, sizeof(char) * 3);
		hex[0] = str[i - 1];
		hex[1] = str[i];
		result[j] = strtol(hex, NULL, 16);
		j++;
	}
}

void
keyXORconst(unsigned char result[], unsigned char *key, int constx)
{
	int i;

	bzero(result, sizeof(char) * (BLOCK_LENGHT + 1));
	bcopy(key, result, SHA1_LENGHT);
	for (i = 0; i < BLOCK_LENGHT; i++) {
		result[i] ^= constx;
	}
}

int
hmacsha1(uint64_t nonce, unsigned char *key, time_t timestamp,
	 unsigned char *hmac)
{
	unsigned int sz;
	unsigned char result1[SHA1_LENGHT + 1];
	EVP_MD_CTX *context;
	unsigned char k_ipad[BLOCK_LENGHT + 1];	
	unsigned char k_opad[BLOCK_LENGHT + 1];	

	memset(result1, 0, sizeof(unsigned char) * (SHA1_LENGHT + 1));
	context = EVP_MD_CTX_new();
	if (!context) {
		err(EXIT_FAILURE, "Cannot allocate memory");
	}
	keyXORconst(k_opad, key, CONST1);
	keyXORconst(k_ipad, key, CONST2);
	if (!EVP_DigestInit(context, EVP_sha1())) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestUpdate(context, k_ipad, sizeof(k_ipad) - 1)) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestUpdate(context, &nonce, NONCE_SIZE)) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestUpdate(context, &timestamp, sizeof(timestamp))) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	sz = EVP_MD_size(EVP_sha1());
	if (!EVP_DigestFinal_ex(context, result1, &sz)
	    || sz != EVP_MD_size(EVP_sha1())) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestInit(context, EVP_sha1())) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestUpdate(context, k_opad, sizeof(k_opad) - 1)) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	if (!EVP_DigestUpdate(context, result1, SHA1_LENGHT)) {
		EVP_MD_CTX_free(context);
        return 0;
	}
	sz = EVP_MD_size(EVP_sha1());
	if (!EVP_DigestFinal_ex(context, hmac, &sz)
	    || sz != EVP_MD_size(EVP_sha1())) {
		EVP_MD_CTX_free(context);
        return 0;
	}

	EVP_MD_CTX_free(context);
    return 1;
}

int
isDigit(char c)
{
	return (c >= '0' && c <= '9');
}

int
isMinus(char c)
{
	return (c >= 'a' && c <= 'z');
}

int
isMayus(char c)
{
	return (c >= 'A' && c <= 'Z');
}

int
loginValid(char *login)
{
	int valid = 1, i;

	if (strlen(login) > LOGIN_SIZE) {
		valid = 0;
	} else {
		for (i = 0; i < strlen(login); i++) {
			if (!isMayus(login[i]) && !isMinus(login[i])
			    && !isDigit(login[i])) {
				valid = 0;
			}
		}
	}
	return valid;
}

int
isStrValid(char *str)
{
	int valid = 1;

	for (; *str != '\0'; str++) {
		if (!isDigit(*str)) {
			valid = 0;
		}
	}
	return valid;
}

int
strToInt(char *str)
{
	int port;

	if (isStrValid(str)) {
		port = (int)strtol(str, NULL, 10);
	} else {
		port = PORT;
		warnx
		    ("Warning, Port %s invalid. We'll try to use default port %d instead",
		     str, PORT);
	}
	return port;
}
