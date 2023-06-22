#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define MAX_SIZE 64
#define MEM_SIZE 1024

char username[MAX_SIZE];
char password[MAX_SIZE];
char temp[MEM_SIZE];

void menu();

void writeInfo()
{
        FILE *fPtr;

        fPtr = fopen("/home/anh/LINUX/LABVII/data.txt", "a");
        if (fPtr == NULL)
        {
                printf("\nUnable to open file.\n");
                exit(0);
        }

        fputs(temp, fPtr);
        fclose(fPtr);
}

int comparePass(char ina[MAX_SIZE], char inb[MAX_SIZE])
{
        if (strcmp(ina, inb) == 0)
                return 0;
        return 1;
}

void findInFile(char uname[MAX_SIZE], char hashPass[MEM_SIZE], int mode)
{
        char tmpUsername[MAX_SIZE], tmpPassMD5[MAX_SIZE], tmpPassSHA1[MAX_SIZE], tmpPassSHA2[MAX_SIZE], tempLine[MEM_SIZE];
        FILE *fPtr;
        int flag;
        char line[MEM_SIZE];
        fPtr = fopen("/home/anh/LINUX/LABVII/data.txt", "r");
        if (fPtr == NULL)
        {
                printf("\nUnable to open file.\n");
                exit(0);
        }

        while (fgets(line, sizeof(line), fPtr))
        {

                sscanf(line, "%s %s %s %s", tmpPassMD5, tmpPassSHA1, tmpPassSHA2, tmpUsername);
                if (strcmp(tmpUsername, uname) == 0)
                {
                        switch (mode)
                        {
                        case 1:
                                flag = comparePass(hashPass, tmpPassMD5);
                                break;
                        case 2:
                                flag = comparePass(hashPass, tmpPassSHA1);
                                break;
                        case 3:
                                flag = comparePass(hashPass, tmpPassSHA2);
                                break;
                        default:
                                break;
                        }
                        break;
                }
        }
        fclose(fPtr);
        if (flag == 0)
        {
                printf("Auth: OK\n");
        }
        else
        {
                printf("Auth: Fail\n");
        }
}

void doHash(int fd, int mode, char *username, char *password)
{
        char buffer[MEM_SIZE];
        memset(temp, 0, sizeof(temp));
        sprintf(buffer, "opt:%d\nusername:%s\npassword:%s\n", mode, username, password);
        write(fd, buffer, strlen(buffer));
        memset(buffer, 0, sizeof(buffer));
        read(fd, buffer, sizeof(buffer));
        strcpy(temp, buffer);
}

void add_info(int fd)
{
        printf("--- Add the account information ---\n");
        printf(" > Enter username: ");
        fgets(username, MAX_SIZE, stdin);
        username[strlen(username) - 1] = '\0';
        printf(" > Enter password: ");
        fgets(password, MAX_SIZE, stdin);
        password[strlen(password) - 1] = '\0';
        doHash(fd, 0, username, password);
}

void verify(int fd, int mode)
{
        printf("--- Verify ---\n");
        printf(" > Enter username: ");
        fgets(username, MAX_SIZE, stdin);
        username[strlen(username) - 1] = '\0';
        printf(" > Enter password: ");
        fgets(password, MAX_SIZE, stdin);
        password[strlen(password) - 1] = '\0';
        doHash(fd, mode, username, password);
        findInFile(username, temp, mode);
}

void menuHash(int fd)
{
        char option;

        while (1)
        {
                printf("------- Hash Mode -------------------\n");
                printf("        1. MD5                       \n");
                printf("        2. SHA1                      \n");
                printf("        3. SHA2                      \n");
                printf("        4. Exit                      \n");
                printf("--------------------------------------\n");

                scanf(" %c", &option);
                getchar();
                printf("Your Option = %c\n", option);

                switch (option)
                {
                case '1':
                        verify(fd, 1);
                        break;
                case '2':
                        verify(fd, 2);
                        break;
                case '3':
                        verify(fd, 3);
                        break;
                case '4':
                        menu();
                        break;
                default:
                        printf("Enter Valid option = %c\n", option);
                        break;
                }
        }
}

void menu()
{
        int fd;
        char buffer[MEM_SIZE], value[MEM_SIZE], optional[MEM_SIZE];
        char option;

        printf("##### Character driver - Hash Data #####\n");
        fd = open("/dev/lab7_hash", O_RDWR);
        if (fd < 0)
        {
                printf("Cannot open device file...\n");
        }

        while (1)
        {
                printf("------- Enter the Option -------------\n");
                printf("        1. Add                        \n");
                printf("        2. Verify                     \n");
                printf("        3. Exit                       \n");
                printf("--------------------------------------\n");

                scanf(" %c", &option);
                getchar();
                printf("Your Option = %c\n", option);

                switch (option)
                {
                case '1':
                        add_info(fd);
                        writeInfo();
                        break;
                case '2':
                        menuHash(fd);
                        break;
                case '3':
                        close(fd);
                        exit(1);
                        break;
                default:
                        printf("Enter Valid option = %c\n", option);
                        break;
                }
        }
}

void main()
{
        menu();
}
