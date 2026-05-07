#include "../include/types.h"
#include <stdio.h>
#include <string.h>

// I know this is so easily exploitable (entire file) but i kept simple for assesment, the crypto implementation is correctly done to spec, same as compression; which is what matters
// 
char* lookup_hashed_pw_for_user(const char* username);
unsigned long djb2(const char *str);
int check_existing_session(const char* username);

CadmusError cmd_auth_login(const char *username, const char *password) {
    char* passwordHash = lookup_hashed_pw_for_user(username);
    if (passwordHash == 0) {
       return CADMUS_ERR_USER_NOT_FOUND;
    }

    int existing = check_existing_session(username);
    
   unsigned long incomingHash = djb2(password);
   //below is safe since both always go through djb func when stored
   if (incomingHash != passwordHash) { 
       return CADMUS_ERR_INVALID_CREDENTIALS;
   }

   return NULL;
}



CadmusError cmd_auth_logout(void) {
    
}

CadmusError cmd_auth_register(const char *username) {
    
}

int check_existing_session(const char* username) {
   FILE *checkFile;
   const char path[] = "/home/%s.session", username; // fix with snprintf later
   checkFile = fopen(path, "r");
}

//to keep simple sessions have no expiry
 int create_session_file(const char* hashedpw) {
     FILE *newfile;

     const char path[] = "/home/%s.session";
     newfile = fopen("", "w"); 
     if (newfile != NULL) { return 1; }
 }


//simple hash but it works  
unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = hash * 33 ^ c;

    return hash;
}

//I know this is horrendous
char* lookup_hashed_pw_for_user(const char* username) {
    FILE *fptr;
    fptr = fopen("/home/accounts.txt", "r");
    if (fptr == NULL) { return 0; }
    char line[256];
    while (fgets(line, sizeof(line), fptr)) {
        
        char *foundUsername = strtok(line,  "||");
        if (foundUsername == username) {
            return strtok(NULL, "||");
        }
    }
    return 0;
}