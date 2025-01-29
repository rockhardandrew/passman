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

void password_gen(uint8_t * buf, int length)
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

struct verifyreturn verify(char password[64])
{
    char passmanpath[500];
    sprintf(passmanpath, "%s/.passman-store", getenv("HOME"));
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
	puts("malloc failed");
	crypto_wipe(uintpass, length);
    }
    char filepath[200];
    sprintf(filepath, "%s/passman-hash", passmanpath);
    FILE *file = fopen(filepath, "rb");
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

void init()
{
    char passmanpath[200];
    sprintf(passmanpath, "%s/.passman-store", getenv("HOME"));
    if (stat(passmanpath, &st) == -1) {
	mkdir(passmanpath, 0770);
    } else {
	printf
	    ("%s already exists, you may have already initialized passman. If you want to initialize again move ~/.passman-store to a new area or delete the directory all together",
	     passmanpath);
	return;
    }
    puts("Enter the password that you want you use for the encryption key");
    char password[64];
    getpasswd(password);
    puts("Confirm password");
    char confirm_password[64];
    getpasswd(confirm_password);
    if (strcmp(password, confirm_password) != 0) {
	puts("passwords don't match");
	return;
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
	puts("malloc failed");
	crypto_wipe(uintpass, length);
    }
    arc4random_buf(salt, 16);
    crypto_argon2i(key, 32, work_area, nb_blocks, nb_iterations, uintpass,
		   length, salt, 16);
    free(work_area);
    uint8_t hash[32];
    crypto_blake2b_general(hash, 32, NULL, 0, key, 32);
    crypto_wipe(key, 32);
    char hashpath[300];
    sprintf(hashpath, "%s/passman-hash", passmanpath);
    FILE *hashfile = fopen(hashpath, "wb");
    if (hashfile == NULL) {
	puts("file couldn't be opened");
	return;
    }
    fwrite(hash, 1, 32, hashfile);
    fwrite(salt, 1, 16, hashfile);
    crypto_wipe(hash, 32);
    fclose(hashfile);
}

void add(char *path)
{
    char password[64];
    puts("put your key password");
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches == 0) {
	puts("the password you entered does not match with the key");
	return;
    }
    puts("put the password you'd like to add");
    char password2[1000];
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
    char passwordpath[300];
    sprintf(passwordpath, "%s/.passman-store/%s", getenv("HOME"), path);
    FILE *passwordfile = fopen(passwordpath, "wb");
    fwrite(mac, 1, 16, passwordfile);
    fwrite(nonce, 1, 24, passwordfile);
    fwrite(encrypted_password, 1, length, passwordfile);
    fclose(passwordfile);
}

void generate(char *path, int length)
{
    uint8_t generatedpass[length];
    password_gen(generatedpass, length);
    char password[64];
    puts("put your key password");
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches == 0) {
	puts("the password you entered does not match with the key");
	return;
    }
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t encrypted_password[length];
    arc4random_buf(nonce, 24);
    crypto_lock(mac, encrypted_password, key.key, nonce, generatedpass,
		length);
    char passwordpath[300];
    sprintf(passwordpath, "%s/.passman-store/%s", getenv("HOME"), path);
    FILE *passwordfile = fopen(passwordpath, "wb");
    fwrite(mac, 1, 16, passwordfile);
    fwrite(nonce, 1, 24, passwordfile);
    fwrite(encrypted_password, 1, length, passwordfile);
    fclose(passwordfile);
}

void walk(char *path, int len)
{
    struct dirent *de;
    DIR *dr = opendir(path);
    if (dr == NULL)		// opendir returns NULL if couldn't open directory
    {
	printf("Could not open current directory");
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
	    int length = strlen(path) + strlen(de->d_name) + 3;
	    char dir[length];
	    sprintf(dir, "%s/%s", path, de->d_name);
	    walk(dir, len);
	} else {
	    printf("%s/%s\n", path + len, de->d_name);
	}
    }
    closedir(dr);
    return;
}

void show(char *path)
{
    puts("put your key password");
    char password[64];
    getpasswd(password);
    struct verifyreturn key = verify(password);
    if (key.matches == 0) {
	puts("the password you entered does not match with the key");
	return;
    }
    uint8_t nonce[24];
    uint8_t mac[16];
    char passwordpath[500];
    sprintf(passwordpath, "%s/.passman-store/%s", getenv("HOME"), path);
    FILE *passfile = fopen(passwordpath, "rb");
    if(passfile == NULL){
    puts("password not found");
    crypto_wipe(key.key, 32);
    return;
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
	return;
    } else {
	for (int i = 0; i < length; i++) {
	    printf("%c", plain_text[i]);
	}
	printf("\n");
	crypto_wipe(plain_text, 12);
	crypto_wipe(key.key, 32);
    }

}

int main(int argc, char *argv[])
{
    if(argv[1] == NULL || strcmp(argv[1], "help") == 0 ){
	printf("Usage:\n\tpassman help\tdisplays help message\n\tpassman generate [name] [length]\tgenerates a password and securely stores it\n\tpassman show [name]\tprints the unencrypted value of a stored password\n\tpassman add\tprompts for a password and securely stores it\n\tpassman list\tlists the passwords that are stored\n");
	return 0;
    }
    if (strcmp(argv[1], "init") == 0) {
	init();
	return 0;
    } else if (strcmp(argv[1], "generate") == 0) {
	if (argc < 4) {
	    puts("not enough arguments passed for generate");
	    return 1;
	}
	generate(argv[2], atoi(argv[3]));
	return 0;
    } else if (strcmp(argv[1], "show") == 0) {
	if (argc < 3) {
	    puts("not enough arguments passed for show");
	    return 1;
	}
	show(argv[2]);
	return 0;
    } else if (strcmp(argv[1], "add") == 0
	       || strcmp(argv[1], "insert") == 0) {
	if (argc < 3) {
	    puts("not enough arguments passed for add/insert");
	    return 1;
	}
	add(argv[2]);
	return 0;
    } else if (strcmp(argv[1], "list") == 0) {
	char path[500];
	sprintf(path, "%s/.passman-store/", getenv("HOME"));
	walk(path, strlen(path)+1);
    } else {
	puts("command not found");
	return 0;
    }
}
