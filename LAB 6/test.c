#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define MEM_SIZE 1024

void doCipher(int fd, int mode, char *value, char *optional)
{
        char buffer[MEM_SIZE];
        sprintf(buffer, "opt:%d\nvalue:%s\noptional:%s\n", mode, value, optional);
        write(fd, buffer, strlen(buffer));
        memset(buffer, 0, sizeof(buffer));
        read(fd, buffer, sizeof(buffer));
        printf("%s", buffer);
}

int main()
{
        int fd;
        char buffer[MEM_SIZE], value[MEM_SIZE], optional[MEM_SIZE];
        char option;

        printf("##### Character driver - Simple encryption algorithms #####\n");
        fd = open("/dev/lab6_cipher", O_RDWR);
        if (fd < 0)
        {
                printf("Cannot open device file...\n");
                return 0;
        }

        while (1)
        {
                printf("        ----- Enter the Option -----                    \n");
                printf("        1. Enter your plain text                        \n");
                printf("        2. Caesar cipher - Encrypt                      \n");
                printf("        3. Mono-alphabetic Substitution - Encrypt       \n");
                printf("        4. Transposition cipher - Encrypt               \n");
                printf("        5. Caesar cipher - Decrypt                      \n");
                printf("        6. Mono-alphabetic Substitution - Decrypt       \n");
                printf("        7. Transposition cipher - Decrypt               \n");
                printf("        0. Exit                                         \n");
                printf("--------------------------------------------------\n");

                scanf(" %c", &option);
                getchar();
                printf("Your Option = %c\n", option);

                switch (option)
                {
                case '1':
                        printf("Enter your plain text: ");
                        fgets(value, MEM_SIZE, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 0, value, optional);
                        printf("\n");
                        break;
                case '2':
                        printf("--- Caesar cipher - Encrypt ---\n");
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 1, value, optional);
                        printf("\n");
                        break;
                case '3':
                        printf("--- Mono-alphabetic Substitution - Encrypt ---\n");
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 2, value, optional);
                        printf("\n");
                        break;
                case '4':
                        printf("--- Transposition cipher - Encrypt ---\n");
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 3, value, optional);
                        printf("\n");
                        break;
                case '5':
                        printf("--- Caesar cipher - Decrypt ---\n");
                        printf(" > Enter cipher text: ");
                        fgets(optional, 100, stdin);
                        optional[strlen(optional) - 1] = '\0';
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 4, value, optional);
                        printf("\n");
                        break;
                case '6':
                        printf("--- Mono-alphabetic Substitution cipher - Decrypt ---\n");
                        printf(" > Enter cipher text: ");
                        fgets(optional, 100, stdin);
                        optional[strlen(optional) - 1] = '\0';
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 5, value, optional);
                        printf("\n");
                        break;
                case '7':
                        printf("--- Transposition cipher - Decrypt ---\n");
                        printf(" > Enter cipher text: ");
                        fgets(optional, 100, stdin);
                        optional[strlen(optional) - 1] = '\0';
                        printf(" > Enter your key: ");
                        fgets(value, 100, stdin);
                        value[strlen(value) - 1] = '\0';
                        doCipher(fd, 6, value, optional);
                        printf("\n");
                        break;
                case '0':
                        close(fd);
                        exit(1);
                        break;
                default:
                        printf("Enter Valid option = %c\n", option);
                        break;
                }
        }
}
