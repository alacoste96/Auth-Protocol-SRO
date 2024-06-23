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
#include <ifaddrs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <math.h>
#include <time.h>
#include "tools.c"
#include <errno.h>

enum {
	MAYUS_DIF = 'a' - 'A',
	BACKLOG = 100,
	TEN_MINUTES = 600,
    FIVE_MINUTES =300,
};

void
mayusToMinus(char *str)
{
	int i;

	for (i = 0; i < strlen(str); i++) {
		if (isMayus(str[i])) {
			str[i] += MAYUS_DIF;
		}
	}
}

void
checkLine(char *readed, char login[], char key[], int line, char *fichname)
{
	char *saveptr = NULL;
	char *token = NULL;

	memset(login, 0, sizeof(char) * (BUFFER + 1));
	memset(key, 0, sizeof(char) * (BUFFER + 1));
	token = strtok_r(readed, ":", &saveptr);
	if (token && strcmp(token, "\n")) {
		strncat(login, token, sizeof(char) * BUFFER);
	}
	token = strtok_r(NULL, ":", &saveptr);
	if (token) {
		mayusToMinus(token);
		strncat(key, token, sizeof(char) * BUFFER);
	}
	if (token) {
		if (!loginValid(login)) {
			fprintf(stderr,
				"login: '%s'\nCannot support special characters or a login bigger than 255 bytes\n",
				login);
			errx(EXIT_FAILURE,
			     "can't parse accounts file, line %d, incorrect login",
			     line);
		}
		key[strlen(key) - 1] = '\0';
		if (strlen(key) != (KEY_CHAR_SIZE)) {
			fprintf(stderr, "key: '%s'\n", key);
			errx(EXIT_FAILURE,
			     "can't parse accounts file, line %d, bad key size (%ld)",
			     line, strlen(key));
		}
		if (!isHexStr(key)) {
			fprintf(stderr, "key: '%s'\n", key);
			errx(EXIT_FAILURE,
			     "can't parse accounts file, line %d, bad key has not hexadecimal chars",
			     line);
		}
	}
}

void
validDatabase(char *database)
{
	FILE *fich;
	char readed[BUFFER + 1];
	char login[BUFFER + 1];
	char key[BUFFER + 1];
	int line = 1;

	if (!(fich = fopen(database, "r"))) {
		err(EXIT_FAILURE, "Cannot open to read %s", database);
	}
	bzero(readed, (BUFFER + 1));
	while ((fgets(readed, (BUFFER + 1), fich)) != NULL) {
		checkLine(readed, login, key, line, database);
		bzero(readed, (BUFFER + 1));
		line++;
	}
	fclose(fich);
}

int
readKey(char *login, char *database, unsigned char key[])
{
	FILE *fich;
	char readed[BUFFER + 1];
	char *saveptr = NULL;
	char *auxkey = NULL;
	int found = 0;

	if (!(fich = fopen(database, "r"))) {
		err(EXIT_FAILURE, "Cannot open to read %s", database);
	}
	memset(key, 0, sizeof(unsigned char) * SHA1_LENGHT + 1);
	bzero(readed, (BUFFER + 1));
	while ((fgets(readed, (BUFFER + 1), fich)) != NULL && !found) {
		auxkey = strtok_r(readed, ":", &saveptr);
		if (auxkey && strcmp(auxkey, "\n")) {
			if (strcmp(auxkey, login) == 0) {
				auxkey = strtok_r(NULL, ":", &saveptr);
				auxkey[strlen(auxkey) - 1] = '\0';
				strToHex(key, auxkey);
				found++;
			}
		}
		if (!found) {
			bzero(readed, (BUFFER + 1));
		}
	}
	fclose(fich);
	return found;
}

int
nonceFound(nonces * database, uint64_t nonce)
{
	int i = 0, found = -1;

	for (i = 0; i < database->lenght; i++) {
		if (nonce == database->nonce[i]) {
			found = i;
		}
	}
	return found;
}

uint64_t
nonceGen(nonces * database)
{
	FILE *source;
	uint64_t nonce;
	size_t count;
	int found, valid = 1;
	time_t timestamp;

	if (!(source = fopen("/dev/random", "r"))) {
		err(EXIT_FAILURE, "Cannot open /dev/random to generate nonces");
	}
	do {
		count = fread(&nonce, sizeof(nonce), 1, source);
		found = nonceFound(database, nonce);
		timestamp = time(NULL);
		if (found != -1) {
			if ((timestamp - database->timestamp[found]) <
			    TEN_MINUTES) {
				valid = 0;
			} else {
				database->timestamp[found] = timestamp;
			}
		} else {
			database->nonce[database->lenght] = nonce;
			database->timestamp[database->lenght] = timestamp;
			database->lenght += 1;
			valid = 1;
		}
	} while (count != 1 && !valid);
	fclose(source);
	return nonce;
}

int
hmacsEquals(unsigned char *str1, unsigned char *str2)
{
	int i, equals;

	equals = 1;
	for (i = 0; i < (SHA1_LENGHT); i++) {
		if (str1[i] != str2[i]) {
			equals = 0;
		}
	}
	return equals;
}

int
authenticated(unsigned char credentials[], uint64_t nonce, char *database,
	      char login[])
{
	time_t timestamp;
	unsigned char verif_hmac[SHA1_LENGHT + 1];
	unsigned char clientHmac[SHA1_LENGHT + 1];
	unsigned char key[SHA1_LENGHT + 1];

	memset(key, 0, sizeof(unsigned char) * SHA1_LENGHT + 1);
	if (!readKey(login, database, key)) {
		return 0;
	}
	memset(clientHmac, 0, sizeof(unsigned char) * SHA1_LENGHT + 1);
	memcpy(clientHmac, credentials,
	       sizeof(unsigned char) * SHA1_LENGHT + 1);
	memset(verif_hmac, 0, sizeof(unsigned char) * SHA1_LENGHT + 1);
	memset(&timestamp, 0, sizeof(timestamp));
	memcpy(&timestamp, credentials + SHA1_LENGHT, sizeof(timestamp));
    if((time(NULL) - timestamp) > FIVE_MINUTES){
        return 3;
    }
    if(!hmacsha1(nonce, key, timestamp, verif_hmac)){
        return 2;
    }
    if(hmacsEquals(verif_hmac, clientHmac)){
		return 1;
	} else {
		return 0;
	}
}

void
errorMSG(char msg[], char login[], char clientIP[])
{
	if (login) {
		fprintf(stderr, "FAILURE, %s from %s\n", login, clientIP);
	} else {
		fprintf(stderr, "FAILURE from %s\n", clientIP);
	}
	warnx("%s", msg);
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		warn("Time out");
	}
}

void
sendResult(int clientfd, char result[], char login[], char clientIP[]){
    int error = 0;

    error = write(clientfd, result, sizeof(char) * RESULT_SIZE + 1);
    if (error < 0) {	
	    errorMSG("Cannot write result", login, clientIP);
	}else{
	    printf("%s, %s from %s\n",result, login, clientIP);
    }
}

void
authenticate(unsigned char credentials[], uint64_t nonce, char *database,
	      int connfd, char clientIP[]){
    int authchecker;
    char login[LOGIN_SIZE + 1];

    memset(login, 0, sizeof(char) * LOGIN_SIZE + 1);
    memcpy(login, credentials + SHA1_LENGHT + TIME_SIZE, 
                    sizeof(char) * LOGIN_SIZE);
    authchecker = authenticated(credentials, nonce, database, login);
    if (authchecker == 1) {
        sendResult(connfd, "SUCCESS", login, clientIP);
	} else {
        sendResult(connfd, "FAILURE", login, clientIP);
        if (authchecker == 2){
            errorMSG("Error at hashing", login, clientIP);           
        } else if (authchecker == 3){
            errorMSG("Clocks are not syncronized", login, clientIP);
        }
    }
}

/*
    Justificación según mi forma de pensar de por qué uso continues en el bucle:
--------------------------------------------------------------------------------
    Cada vez que sucede un error en el server, es interesante que éste no deje
    de dar servicio. Por ello, cuando un error ocurre, se avisa de cuál ha sido,
    se cierra el socket pertinente y se vuelve al punto inicial donde el servidor
    está aceptando conexiones. Para evitar que el servidor haga comprobaciones 
    innecesarias he pensado que lo más conveniente sea que inmediatamente
    se salte al inicio del bucle infinito usando contiue. Si lo controlase de 
    otra manera, tendría que involucrar alguna variable adicional o como poco,
    comprobaciones de que ha habido un error anteriormente, haciendo que el 
    servidor pierda tiempo innecesario y ensuciando el código. Bien es cierto 
    que para un programa pequeño como este no se nota; pero si lo llevamos
    a un servidor de verdad con un código gigante, sería un problema que pierda
    tiempo.
--------------------------------------------------------------------------------
*/

int
main(int argc, char *argv[])
{
	int sockfd, connfd;
	int port = PORT;
	unsigned int len;
	uint64_t nonce;
	nonces database;
	struct sockaddr_in servaddr, client;
	unsigned char credentials[SHA1_LENGHT + TIME_SIZE + LOGIN_SIZE + 1];
	char clientIP[INET_ADDRSTRLEN];

	if (argc <= 3) {
		if (argc == 3) {
			port = strToInt(argv[2]);
		}
		validDatabase(argv[1]);
	} else {
		errx(EXIT_FAILURE, "Incorrect number of arguments");
	}
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		err(EXIT_FAILURE, "[SERVER]Socket creation failed");
	}
    init(&servaddr, port, &database, "127.0.0.1");
	if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
		err(EXIT_FAILURE, "[SERVER]: socket bind failed");
	}
	if (listen(sockfd, BACKLOG) != 0) {
		err(EXIT_FAILURE, "[SERVER]: socket listen failed");
	}
	printf("Server listening at IP: %s. Port: %d\n", 
            inet_ntoa(servaddr.sin_addr), port);
	len = sizeof(client);
	while (1) {
		connfd = accept(sockfd, (struct sockaddr *)&client, &len);
		if (connfd < 0) {
			errorMSG("Connection failed", NULL, NULL);
			continue;
		}
		if(!configTimeOut(connfd)){
            errorMSG("setsockopt failed", NULL, clientIP);
            close(connfd);
            continue;
        }
		nonce = nonceGen(&database);
		if (write(connfd, &nonce, sizeof(nonce)) < 0) {
			errorMSG("Cannot write nonce", NULL, clientIP);
			close(connfd);
			continue;
		}
        memset(credentials, 0, 
            sizeof(char) * (SHA1_LENGHT + TIME_SIZE + LOGIN_SIZE + 1));
		if (read(connfd, credentials, sizeof(credentials)) < 0) {
			errorMSG("Cannot read credentials", NULL, clientIP);
			close(connfd);
			continue;
		}
        inet_ntop(AF_INET, &client, clientIP, INET_ADDRSTRLEN);
		authenticate(credentials, nonce, argv[1], connfd, clientIP);
		close(connfd);
	}
	exit(EXIT_SUCCESS);
}
