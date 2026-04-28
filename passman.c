/*
Copyright (c) 2020 Andrew Bonner

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <stdint.h>
#include "third-party/monocypher.h"
#include <dirent.h>
#include "argon2i-settings.h"
#if defined(__linux__)
uint32_t arc4random_uniform(uint32_t upper_bound);
void arc4random_buf(void *buf, size_t nbytes);
#endif
// return value for verify()
struct verifyreturn {
    uint8_t key[32];
    int matches;
};
struct stat st = { 0 };

char path[4096];

void printusage()
{
    fputs
	("Usage:\n\tpassman help\tdisplays help message\n\tpassman generate [name] [length]\tgenerates a password and securely stores it\n\tpassman show [name]\tprints the unencrypted value of a stored password\n\tpassman add\tprompts for a password and securely stores it\n\tpassman list\tlists the passwords that are stored\n",
	 stderr);
}

void password_gen(uint8_t *buf, int length)
{
    char characters[81] =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~=+%^*()[]{}/!@#$?|";
    int random_num;
    for (int i = 0; i < length; i++) {
	random_num = arc4random_uniform(81);
	buf[i] = characters[random_num];
    }
}

int getpasswd(char password[64])
{
    struct termios oflags, nflags;

    /* disabling echo */
    tcgetattr(fileno(stdin), &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
	perror("tcsetattr");
	return EXIT_FAILURE;
    }

    fgets(password, 64, stdin);
    password[strlen(password) - 1] = 0;
    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
	perror("tcsetattr");
	return EXIT_FAILURE;
    }
    return 0;
}

int initpath(char *file)
{
    struct stat st = { 0 };
    snprintf(path, 4096, "%s/.passman-store/%s", getenv("HOME"), file);
    /* return 1 if .passman-store exists and 0 if it doesn't */
    if (stat(path, &st) == -1) {
	return 0;
    } else {
	return 1;
    }
}

struct verifyreturn verify(char password[64])
{
    int exists = initpath("passman-hash");
    struct verifyreturn returnval;
    int length = strlen(password);
    uint8_t uintpass[length + 1];
// Converts from char to uint8_t
    for (int i = 0; i < length; i++) {
	uintpass[i] = password[i];
    }
    uint8_t salt[16];
    crypto_wipe(password, length);
    void *work_area = malloc(nb_blocks * 1024);	/* Work area       */
    if (work_area == NULL) {
	/* Handle malloc() failure */
	/* Wipe secrets if they are no longer needed */
	fputs("malloc failed\n", stderr);
	crypto_wipe(uintpass, length);
	returnval.matches = -1;
	return returnval;
    }
    FILE *file = fopen(path, "rb");
    uint8_t filehash[32];
    fread(filehash, 1, 32, file);
    fread(salt, 1, 16, file);
    fclose(file);
    crypto_argon2i(returnval.key, 32, work_area, nb_blocks, nb_iterations,
		   uintpass, length, salt, 16);
    free(work_area);
    crypto_wipe(uintpass, length);
    uint8_t hash[32];
    crypto_blake2b_general(hash, 32, NULL, 0, returnval.key, 32);
    int matches = crypto_verify32(hash, filehash);
    if (matches == 0) {
	returnval.matches = 1;
    } else {
	returnval.matches = 0;
    }
    return returnval;
}

int init()
{
    int exists = initpath("");
    if (exists) {
	fputs
	    ("~/.passman-store already exists passman has already been initialized.\n",
	     stderr);
	return 1;
    } else {
	mkdir(path, 0770);
    }
    fputs
	("Enter the password that you want you use for the encryption key\n",
	 stderr);
    char password[64];
    getpasswd(password);
    fputs("Confirm password", stderr);
    char confirm_password[64];
    getpasswd(confirm_password);
    if (strcmp(password, confirm_password) != 0) {
	fputs("passwords don't match\n", stderr);
	return 1;
    }
    uint8_t key[32];
    int length = strlen(password);
    uint8_t uintpass[length];
// Converts from char to uint8_t
    for (int i = 0; i < length; i++) {
	uintpass[i] = password[i];
    }
    uint8_t salt[16];
    crypto_wipe(password, length);
    void *work_area = malloc(nb_blocks * 1024);	/* Work area       */
    if (work_area == NULL) {
	/* Handle malloc() failure */
	/* Wipe secrets if they are no longer needed */
	fputs("malloc failed\n", stderr);
	crypto_wipe(uintpass, length);
	return 1;
    }
    arc4random_buf(salt, 16);
    crypto_argon2i(key, 32, work_area, nb_blocks, nb_iterations, uintpass,
		   length, salt, 16);
    free(work_area);
    uint8_t hash[32];
    crypto_blake2b_general(hash, 32, NULL, 0, key, 32);
    crypto_wipe(key, 32);
    initpath("passman-hash");
    FILE *hashfile = fopen(path, "wb");
    if (hashfile == NULL) {
	fputs("file couldn't be opened\n", stderr);
	return 1;
    }
    fwrite(hash, 1, 32, hashfile);
    fwrite(salt, 1, 16, hashfile);
    crypto_wipe(hash, 32);
    fclose(hashfile);
    return 0;
}

int add(char *pwpath)
{
    char password[64];
    fputs("put your key password\n", stderr);
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches == 0) {
	fputs("the password you entered does not match with the key\n",
	      stderr);
	return 1;
    }
    fputs("put the password you'd like to add\n", stderr);
    char password2[64];
    getpasswd(password2);
    uint8_t nonce[24];
    uint8_t mac[16];
    int length = strlen(password2);
    uint8_t encrypted_password[length];
    uint8_t uintpassword[length];
    for (int i = 0; i < length; i++) {
	uintpassword[i] = password2[i];
    }
    crypto_wipe(password2, length);
    arc4random_buf(nonce, 24);
    crypto_lock(mac, encrypted_password, key.key, nonce, uintpassword,
		length);
    crypto_wipe(key.key, 32);
    crypto_wipe(uintpassword, length);
    int exists = initpath(pwpath);
    if (exists) {
	fputs("password already exists, try deleting it first\n", stderr);
	return 1;
    }
    FILE *passwordfile = fopen(path, "wb");
    fwrite(mac, 1, 16, passwordfile);
    fwrite(nonce, 1, 24, passwordfile);
    fwrite(encrypted_password, 1, length, passwordfile);
    fclose(passwordfile);
    return 0;
}

int generate(char *pwpath, int length)
{
/* since int length is created with atoi make sure nones fishy */
    if (length < 1 || length > 128) {
	printusage();
	return 1;
    }

    uint8_t generatedpass[length];
    password_gen(generatedpass, length);
    char password[64];
    fputs("put your key password\n", stderr);
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches != 1) {
	fputs("the password you entered does not match with the key\n",
	      stderr);
	return 1;
    }
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t encrypted_password[length];
    arc4random_buf(nonce, 24);
    crypto_lock(mac, encrypted_password, key.key, nonce, generatedpass,
		length);
    int exists = initpath(pwpath);
    if (exists) {
	fputs("password already exists, try deleting it first\n", stderr);
	return 1;
    }
    FILE *passwordfile = fopen(path, "wb");
    if (passwordfile == NULL) {
	fputs("failed to open path\n", stderr);
	return 1;
    }
    fwrite(mac, 1, 16, passwordfile);
    fwrite(nonce, 1, 24, passwordfile);
    fwrite(encrypted_password, 1, length, passwordfile);
    fclose(passwordfile);
    return 0;
}

/* similar to strncpy but you can specify which index to start at 
 * I created this function because sometimes you need to concatinate while also removing data */
void strwrite(char *dest, char *src, int start, int maxsize)
{
    int size = strlen(src);
    for (int i = 0; i < maxsize; i++) {
	if (i > size) {
	    dest[i + start] = '\0';
	} else {
	    dest[i + start] = src[i];
	}
    }
}

void walk(char *leadingpath, int len, int issubdir)
{
    if (leadingpath != NULL) {
	int pathlen = strlen(path);
	path[pathlen] = '/';
	strwrite(path, leadingpath, pathlen + 1, 4094 - pathlen);
    }
    struct dirent *de;
    DIR *dr = opendir(path);
    if (dr == NULL)		// opendir returns NULL if couldn't open directory
    {
	perror("Could not open current directory");
	return;
    }
    while ((de = readdir(dr)) != NULL) {
	if (strcmp(de->d_name, ".") == 0) {
	    /* do nothing */
	} else if (strcmp(de->d_name, "..") == 0) {
	    /* do nothing */
	} else if (strcmp(de->d_name, "passman-hash") == 0) {
	    /* do nothing */
	} else if (de->d_type == DT_DIR) {
	    walk(de->d_name, len, 1);
	} else {
	    if (issubdir) {
		printf("%s/%s\n", path + len + 1, de->d_name);
	    } else {
		puts(de->d_name);
	    }
	}
    }
    if (leadingpath != NULL) {
	*strrchr(path, '/') = '\0';
    }
    closedir(dr);
    return;
}

int show(char *pwpath)
{
    fputs("put your key password\n", stderr);
    char password[64];
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches == 0) {
	fputs("the password you entered does not match with the key\n",
	      stderr);
	return 1;
    }
    uint8_t nonce[24];
    uint8_t mac[16];
    int exists = initpath(pwpath);
    if (!exists) {
	fputs("password doesn't exist", stderr);
	crypto_wipe(key.key, 32);
	return 1;
    }
    FILE *passfile = fopen(path, "rb");
    if (passfile == NULL) {
	fputs("failed to open file\n", stderr);
	crypto_wipe(key.key, 32);
	return 1;
    }
    fseek(passfile, 0, SEEK_END);
    long filesize = ftell(passfile);
    fseek(passfile, 0, SEEK_SET);
    fread(mac, 1, 16, passfile);
    fread(nonce, 1, 24, passfile);
    int length = filesize - 40;
    uint8_t uint_password[length];
    fread(uint_password, 1, length, passfile);
    fclose(passfile);
    uint8_t plain_text[length + 1];
    if (crypto_unlock
	(plain_text, key.key, nonce, mac, uint_password, length)) {
	printf("message is corrupted\n");
	crypto_wipe(key.key, 32);
	return 1;
    } else {
	for (int i = 0; i < length; i++) {
	    printf("%c", plain_text[i]);
	}
	printf("\n");
	crypto_wipe(plain_text, 12);
	crypto_wipe(key.key, 32);
    }
    return 0;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
	printusage();
	return 0;
    } else if (strcmp(argv[1], "help") == 0) {
	printusage();
	return 0;
    } else if (strcmp(argv[1], "generate") == 0 && argc > 2) {
	if (argc == 3) {
	    return generate(argv[2], 15);
	} else {
	    return generate(argv[2], atoi(argv[3]));
	}
    } else if (strcmp(argv[1], "add") == 0 && argc > 2) {
	add(argv[2]);
    } else if (strcmp(argv[1], "init") == 0) {
	return init();
    } else if (strcmp(argv[1], "show") == 0 && argc > 2) {
	return show(argv[2]);
    } else if (strcmp(argv[1], "list") == 0) {
	initpath("");
	walk(NULL, strlen(path), 0);
	return 0;
    } else {
	printusage();
	return 1;
    }
}
