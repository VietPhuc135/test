#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#define DRIVER_AUTHOR "tuananh"
#define MEM_SIZE 1024

char opt[1], plainText[MEM_SIZE], cipherText[MEM_SIZE], value[MEM_SIZE];
static int mode;
static int keyKA;
static char keyKB[27];
static int keyKC[100], sizeKC;
static char alphabet[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

dev_t dev_number = 0;
static struct class *device_class;
static struct cdev *cdev;
uint8_t *kernel_buffer;
typedef struct
{
     char t[100];
} textStruct;

static int driver_open(struct inode *inode, struct file *flip);
static int driver_release(struct inode *inode, struct file *filp);
static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off);
static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off);
void charArrToIntArr(void);
textStruct caesarCipher(char data[MEM_SIZE], int mode);
textStruct monoAlphabeticSubstitutionCipher(char data[MEM_SIZE], char plainKey[26], char subKey[26]);
textStruct transpositionCipher(char data[MEM_SIZE], int mode);

static struct file_operations fops =
    {
        .owner = THIS_MODULE,
        .read = driver_read,
        .write = driver_write,
        .open = driver_open,
        .release = driver_release,
};

static int driver_open(struct inode *inode, struct file *flip)
{
     printk("Open\n");
     return 0;
}

static int driver_release(struct inode *inode, struct file *filp)
{
     printk("Release\n");
     return 0;
}

static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off)
{
     char buffer[MEM_SIZE];
     textStruct result;

     switch (mode)
     {
     case 0:
          strcpy(plainText, value);
          sprintf(buffer, "# Plaintext: %s", plainText);
          break;
     case 1:
          kstrtoint(value, 0, &keyKA);
          result = caesarCipher(plainText, 0);
          sprintf(buffer, "# Encrypted Data: %s", result.t);
          break;
     case 2:
          strncpy(keyKB, value, 26);
          result = monoAlphabeticSubstitutionCipher(plainText, alphabet, keyKB);
          sprintf(buffer, "# Encrypted Data: %s", result.t);
          break;
     case 3:
          charArrToIntArr();
          sizeKC = strlen(value) / 2 + 1;
          result = transpositionCipher(plainText, 0);
          sprintf(buffer, "# Encrypted Data: %s", result.t);
          break;
     case 4:
          kstrtoint(value, 0, &keyKA);
          result = caesarCipher(cipherText, 1);
          sprintf(buffer, "# Decrypted Data: %s", result.t);
          break;
     case 5:
          strcpy(keyKB, value);
          result = monoAlphabeticSubstitutionCipher(cipherText, keyKB, alphabet);
          sprintf(buffer, "# Decrypted Data: %s", result.t);
          break;
     case 6:
          charArrToIntArr();
          sizeKC = strlen(value) / 2 + 1;
          result = transpositionCipher(cipherText, 1);
          sprintf(buffer, "# Decrypted Data: %s", result.t);
          break;
     default:
          break;
     }

     copy_to_user(user_buf, buffer, MEM_SIZE);
     return 0;
}
static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off)
{
     copy_from_user(kernel_buffer, user_buf, len);
     memset(opt, 0, sizeof(opt));
     memset(value, 0, sizeof(value));
     sscanf(kernel_buffer, "opt:%s\nvalue:%26[^\n]\noptional:%26[^\n]", opt, value, cipherText);
     kstrtoint(opt, 0, &mode);
     return 0;
}

void charArrToIntArr(void)
{
     int i, j = 0;
     for (i = 0; value[i] != 0; i++)
     {
          if (!isdigit(value[i]))
          {
               continue;
          }
          keyKC[j] = value[i] - '0';
          j++;
     }
}

textStruct caesarCipher(char data[MEM_SIZE], int mode)
{
     textStruct result;
     int i;
     strcpy(result.t, data);
     for (i = 0; i < strlen(result.t); i++)
     {
          if (isalpha(result.t[i]))
          {
               result.t[i] = (mode == 0) ? (result.t[i] + keyKA) : (result.t[i] - keyKA);
               while (!isalpha(result.t[i]))
                    result.t[i] = (mode == 0) ? (result.t[i] - 26) : (result.t[i] + 26);
          }
     }
     return result;
}

textStruct monoAlphabeticSubstitutionCipher(char data[MEM_SIZE], char plainKey[26], char subKey[26])
{
     textStruct result;
     int i, j, len = strlen(data);

     for (i = 0; i < len; i++)
     {
          printk("I: %d", i);
          for (j = 0; j < 26; j++)
          {
               if (!isalpha(data[i]))
               {
                    result.t[i] = 32;
                    continue;
               }

               if (plainKey[j] == toupper(data[i]))
               {
                    if (islower(data[i]))
                    {
                         result.t[i] = subKey[j] + 32;
                    }
                    else
                    {
                         result.t[i] = subKey[j];
                    }
               }
          }
     }
     return result;
}

textStruct transpositionCipher(char data[MEM_SIZE], int mode)
{
     textStruct result;
     int i, count = 0;
     char buffer[100];

     if (sizeKC == strlen(data))
     {
          for (i = 0; i < strlen(plainText); i++)
          {
               if (mode == 0)
               {
                    buffer[i] = data[keyKC[i]];
               }
               else
               {
                    buffer[keyKC[i]] = data[i];
               }
               count++;
          }
     }

     buffer[count] = '\0';
     strcpy(result.t, buffer);
     return result;
}

static int __init char_driver_init(void)
{
     alloc_chrdev_region(&dev_number, 0, 1, "lab06");
     printk("Insert character driver successfully. major(%d), minor(%d)\n", MAJOR(dev_number), MINOR(dev_number));

     device_class = class_create(THIS_MODULE, "lab06");
     device_create(device_class, NULL, dev_number, NULL, "lab6_cipher");

     kernel_buffer = kmalloc(MEM_SIZE, GFP_KERNEL);

     cdev = cdev_alloc();
     cdev_init(cdev, &fops);
     cdev_add(cdev, dev_number, 1);

     return 0;
}
static void __exit char_driver_exit(void)
{
     cdev_del(cdev);
     kfree(kernel_buffer);
     device_destroy(device_class, dev_number);
     class_destroy(device_class);
     unregister_chrdev_region(dev_number, 1);
     printk("Remove character driver successfully.\n");
}

module_init(char_driver_init);
module_exit(char_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
