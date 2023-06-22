#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MEM_SIZE 1024
#define MAX_SIZE 64
#define LENGTH 2048

volatile sig_atomic_t flag = 0;
int sockfd = 0;

char driverMessage[MEM_SIZE];
char username[MAX_SIZE];
char password[MAX_SIZE];
int fd;

int comparePass(char ina[MAX_SIZE], char inb[MAX_SIZE])
{
     if (strcmp(ina, inb) == 0)
          return 0;
     return 1;
}

int findInFile(char uname[MAX_SIZE], char hashPass[MEM_SIZE])
{
     char tmpUsername[MAX_SIZE], tmpPassHashed[MAX_SIZE], tempLine[MAX_SIZE];
     FILE *fPtr;
     int flag;
     char line[MEM_SIZE];
     fPtr = fopen("/home/anh/LINUX/LABIX/driver/data.txt", "r");
     if (fPtr == NULL)
     {
          printf("\nUnable to open file.\n");
          exit(0);
     }

     while (fgets(line, sizeof(line), fPtr))
     {

          sscanf(line, "%s %s", tmpUsername, tmpPassHashed);
          if (strcmp(tmpUsername, uname) == 0)
          {
               flag = comparePass(hashPass, tmpPassHashed);
          }
          break;
     }

     fclose(fPtr);
     return flag;
}

void writeInfo(char username[MAX_SIZE], char password[MEM_SIZE])
{
     char temp[MEM_SIZE];
     sprintf(temp, "%s %s\n", username, password);
     FILE *fPtr;

     fPtr = fopen("/home/anh/LINUX/LABIX/driver/data.txt", "a");
     if (fPtr == NULL)
     {
          printf("\nUnable to open file.\n");
          exit(0);
     }

     fputs(temp, fPtr);
     fclose(fPtr);
}

void handlerDriver(int fd, int mode, char *value)
{
     char buffer[MEM_SIZE];
     memset(driverMessage, 0, strlen(driverMessage));
     sprintf(buffer, "opt:%d\nvalue:%s\n", mode, value);
     write(fd, buffer, strlen(buffer));
     memset(buffer, 0, sizeof(buffer));
     read(fd, buffer, sizeof(buffer));
     strcpy(driverMessage, buffer);
}

void str_overwrite_stdout()
{
     printf("%s", "> ");
     fflush(stdout);
}

void str_trim_lf(char *arr, int length)
{
     int i;
     for (i = 0; i < length; i++)
     {
          if (arr[i] == '\n')
          {
               arr[i] = '\0';
               break;
          }
     }
}

void catch_ctrl_c_and_exit(int sig)
{
     flag = 1;
}

void send_msg_handler()
{
     char message[LENGTH] = {};
     char buffer[LENGTH + 32] = {};

     while (1)
     {
          str_overwrite_stdout();
          fgets(message, LENGTH, stdin);
          str_trim_lf(message, LENGTH);
          handlerDriver(fd, 2, message);

          if (strcmp(message, "exit") == 0)
          {
               break;
          }
          else
          {
               sprintf(buffer, "Sender:%s\nMessage:%s\n", username, driverMessage);
               send(sockfd, buffer, strlen(buffer), 0);
          }

          bzero(message, LENGTH);
          bzero(driverMessage, LENGTH);
          bzero(buffer, LENGTH + 64);
     }
     catch_ctrl_c_and_exit(2);
}

void recv_msg_handler()
{
     char cipherText[LENGTH] = {};
     char message[MAX_SIZE];
     char sender[MAX_SIZE];
     while (1)
     {
          int receive = recv(sockfd, cipherText, LENGTH, 0);
          if (receive > 0)
          {

               sscanf(cipherText, "Sender:%s\nMessage:%s\n", sender, message);
               handlerDriver(fd, 3, message);
               printf("%s: ", sender);
               printf("%s\n", driverMessage);
               str_overwrite_stdout();
          }
          else if (receive == 0)
          {
               break;
          }

          memset(sender, 0, strlen(sender));
          memset(cipherText, 0, strlen(cipherText));
          memset(message, 0, strlen(message));
          memset(driverMessage, 0, strlen(driverMessage));
     }
}

void handleSocket(char *username)
{
     char *ip = "127.0.0.1";
     int port = 4212;
     struct sockaddr_in server_addr;

     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     server_addr.sin_family = AF_INET;
     server_addr.sin_addr.s_addr = inet_addr(ip);
     server_addr.sin_port = htons(port);

     int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
     if (err == -1)
     {
          printf("ERROR: Can't Connect\n");
          return EXIT_FAILURE;
     }

     send(sockfd, username, 32, 0);

     printf("---- WELCOME ----\n");

     pthread_t send_msg_thread;
     if (pthread_create(&send_msg_thread, NULL, (void *)send_msg_handler, NULL) != 0)
     {
          printf("ERROR: PTHREAD\n");
          return EXIT_FAILURE;
     }

     pthread_t recv_msg_thread;
     if (pthread_create(&recv_msg_thread, NULL, (void *)recv_msg_handler, NULL) != 0)
     {
          printf("ERROR: PTHREAD\n");
          return EXIT_FAILURE;
     }

     while (1)
     {
          if (flag)
          {
               printf("\nBye\n");
               break;
          }
     }

     close(sockfd);
}

int main()
{
     int auth;
     char buffer[MEM_SIZE], value[MEM_SIZE], data[MEM_SIZE];
     char hashMode[4];
     char cipherMode[4];
     char message[MEM_SIZE];
     char option;

     printf("##### Character driver - Chat with Encryption #####\n");
     fd = open("/dev/lab9_cipher", O_RDWR);
     if (fd < 0)
     {
          printf("Cannot open device file...\n");
          return 0;
     }

     while (1)
     {
          printf("        ----- Enter the Option -----      \n");
          printf("        1. Setup                          \n");
          printf("        2. Add account                    \n");
          printf("        3. Chat                           \n");
          printf("        4. Exit                           \n");
          printf("--------------------------------------------------\n");

          scanf(" %c", &option);
          getchar();
          printf("Your Option = %c\n", option);

          switch (option)
          {
          case '1':

               printf("--- Config ---\n");
               printf(" > Enter hash mode (MD5|SH1|SH2): ");
               fgets(hashMode, MAX_SIZE, stdin);
               hashMode[strlen(hashMode) - 1] = '\0';
               printf(" > Enter cipher mode (AES|DES): ");
               fgets(cipherMode, MAX_SIZE, stdin);
               cipherMode[strlen(cipherMode) - 1] = '\0';
               sprintf(value, "%s%s", hashMode, cipherMode);
               handlerDriver(fd, 0, value);
               printf("\n");
               printf("%s \n", driverMessage);
               break;
          case '2':
               printf("--- Add the account information ---\n");
               printf(" > Enter username: ");
               fgets(username, MAX_SIZE, stdin);
               username[strlen(username) - 1] = '\0';
               printf(" > Enter password: ");
               fgets(password, MAX_SIZE, stdin);
               password[strlen(password) - 1] = '\0';
               sprintf(value, "%s %s", username, password);
               handlerDriver(fd, 1, value);
               writeInfo(username, driverMessage);
               printf("\n");
               break;
          case '3':
               printf("--- Sign In ---\n");
               printf(" > Enter username: ");
               fgets(username, MAX_SIZE, stdin);
               username[strlen(username) - 1] = '\0';
               printf(" > Enter password: ");
               fgets(password, MAX_SIZE, stdin);
               password[strlen(password) - 1] = '\0';
               sprintf(value, "%s %s", username, password);
               handlerDriver(fd, 1, value);
               auth = findInFile(username, driverMessage);
               printf("\n");
               if (auth == 0)
               {
                    handleSocket(username);
               }

               break;
          case '4':
               close(fd);
               exit(1);
               break;
          default:
               printf("Enter Valid option = %c\n", option);
               break;
          }
     }
}
