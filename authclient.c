#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "tools.c"
#include <errno.h>

int
setCredentials(unsigned char credentials[], char *login, unsigned char key[],
	       uint64_t nonce)
{
	time_t timestamp;

	timestamp = time(NULL);
	memset(credentials, 0,
	       sizeof(char) * (SHA1_LENGHT + LOGIN_SIZE + TIME_SIZE + 1));
	if(!hmacsha1(nonce, key, timestamp, credentials)){
        return 0;
    }
	memcpy(credentials + SHA1_LENGHT, &timestamp, sizeof(timestamp));
	memcpy(credentials + SHA1_LENGHT + sizeof(timestamp), login,
	       sizeof(char) * strlen(login));
    return 1;
}

void
errorMSG(char msg[])
{
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		warn("Time out");
	}
	warn("%s", msg);
	fprintf(stderr, "AUTHENTICATION: FAILURE\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *server_addr;
	int port;
	uint64_t nonce;
	int sockfd;
	struct sockaddr_in servaddr;
	unsigned char credentials[SHA1_LENGHT + TIME_SIZE + LOGIN_SIZE + 1];
	unsigned char key[SHA1_LENGHT + 1];
	char result[RESULT_SIZE + 1];

	if (argc != 5) {
		errx(EXIT_FAILURE, "Incorrect number of arguments.");
	}
	if (strlen(argv[2]) != KEY_CHAR_SIZE) {
		errx(EXIT_FAILURE, "bad key size");
	}
	if (isHexStr(argv[2])) {
		strToHex(key, argv[2]);
	} else {
		errx(EXIT_FAILURE, "Key has not hexadecimal numbers");
	}
	if (!loginValid(argv[1])) {
		fprintf(stderr, "Login: %s\n", argv[1]);
		errx(EXIT_FAILURE,
		     "Can't parse login name, cannot support special chars and names bigger than 255 bytes");
	}
	server_addr = argv[3];
	port = strToInt(argv[4]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
        errorMSG("Cannot create socket");
	}
	if(!configTimeOut(sockfd)){
        close(sockfd);
        errorMSG("setsockopt failed");
    }
    init(&servaddr, port, NULL, server_addr);
	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
		close(sockfd);
		errorMSG("Connection failed");
	}
	if (read(sockfd, &nonce, sizeof(nonce)) < 0) {
		close(sockfd);
		errorMSG("Can't receive nonce");
	}
	if(!setCredentials(credentials, argv[1], key, nonce)){
        close(sockfd);
        errorMSG("Error at hashing");
    }
	if (write(sockfd, credentials, sizeof(credentials)) < 0) {
		close(sockfd);
		errorMSG("Can't write credentials");
	}
	memset(result, 0, sizeof(char) * RESULT_SIZE + 1);
	if (read(sockfd, result, RESULT_SIZE) < 0) {
		close(sockfd);
		errorMSG("Can't receive result");
	}
	printf("AUTENTICATION: %s\n", result);
	close(sockfd);
	exit(EXIT_SUCCESS);
}
