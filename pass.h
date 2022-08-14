#ifndef __PASS_H
#define __PASS_H

#define MAX_PASS_SIZE 4096

// generate creates a password with the given size. The 
// returned string will need to be freed by the caller.
char* generate_password(const int size);

// check checks to see if the given password meets 
// complexity requirements for upper, lower, numbers,
// special characters, and dictionary words.
void check(const char *pass);

#endif /* __PASS_H  */
