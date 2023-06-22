#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/ctype.h>

#define DRIVER_AUTHOR "tuananh"
#define MEM_SIZE 1024
#define AES_BLOCK_SIZE 16
char opt[1], plainText[128], plainTextAsHex[256], cipherText[128], cipherTextasHex[256], value[128], key[16];
int mode;
dev_t dev_number = 0;
static struct class *device_class;
static struct cdev *cdev;
uint8_t *kernel_buffer;

static int driver_open(struct inode *inode, struct file *flip);
static int driver_release(struct inode *inode, struct file *filp);
static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off);
static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off);

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

void toHexString(char input[MEM_SIZE], int len, char output[MEM_SIZE])
{
     int i;
     memset(output, 0, strlen(output));
     for (i = 0; i < len; i++)
     {
          sprintf(output, "%s%02hhx", output, input[i]);
     }
}

int hexToUnicode(char *in, int len, char *out)
{
     int i;
     int converter[105];
     converter['0'] = 0;
     converter['1'] = 1;
     converter['2'] = 2;
     converter['3'] = 3;
     converter['4'] = 4;
     converter['5'] = 5;
     converter['6'] = 6;
     converter['7'] = 7;
     converter['8'] = 8;
     converter['9'] = 9;
     converter['a'] = 10;
     converter['b'] = 11;
     converter['c'] = 12;
     converter['d'] = 13;
     converter['e'] = 14;
     converter['f'] = 15;

     for (i = 0; i < len; i = i + 2)
     {
          char byte = converter[(int)in[i]] << 4 | converter[(int)in[i + 1]];
          out[i / 2] = byte;
     }

     return 0;
}

void doAESCipherEN(char inpuData[MEM_SIZE], char outputData[MEM_SIZE])
{
     struct crypto_cipher *tfm;
     int numOfCipher, lenOutput, i, j = 0;
     int lenData = strlen(inpuData);
     char temp[MEM_SIZE];
     numOfCipher = lenData / 16;
     numOfCipher += (lenData % 16 == 0) ? 0 : 1;

     tfm = crypto_alloc_cipher("aes", 0, 0);
     crypto_cipher_setkey(tfm, key, 16);

     for (i = 0; i < numOfCipher; i++)
     {
          crypto_cipher_encrypt_one(tfm, &temp[j], &inpuData[j]);
          j += 16;
     }
     lenOutput = (lenData % 16 == 0) ? lenData : (lenData + (16 - (lenData % 16)));
     temp[lenOutput] = '\0';
     toHexString(temp, lenOutput, outputData);
     crypto_free_cipher(tfm);
}

void doAESCipherDE(char inpuData[MEM_SIZE], char outputData[MEM_SIZE])
{

     struct crypto_cipher *tfm;
     int numOfCipher, i, j = 0;
     int lenData = strlen(inpuData);
     char temp[MEM_SIZE];
     numOfCipher = (lenData / 16 < 1) ? 1 : (lenData / 16);

     tfm = crypto_alloc_cipher("aes", 0, 0);
     crypto_cipher_setkey(tfm, key, 16);

     for (i = 0; i < numOfCipher; i++)
     {
          crypto_cipher_decrypt_one(tfm, &temp[j], &inpuData[j]);
          j += 16;
     }
     strcpy(outputData, temp);
     crypto_free_cipher(tfm);
}

void doDESCipherEN(char inpuData[MEM_SIZE], char outputData[MEM_SIZE])
{
     struct crypto_cipher *tfm;
     int numOfCipher, lenOutput, i, j = 0;
     int lenData = strlen(inpuData);
     char temp[MEM_SIZE];
     numOfCipher = lenData / 8;
     numOfCipher += (lenData % 8 == 0) ? 0 : 1;

     tfm = crypto_alloc_cipher("des", 0, 0);
     crypto_cipher_setkey(tfm, key, 8);

     for (i = 0; i < numOfCipher; i++)
     {
          crypto_cipher_encrypt_one(tfm, &temp[j], &inpuData[j]);
          j += 8;
     }
     lenOutput = (lenData % 8 == 0) ? lenData : (lenData + (8 - (lenData % 8)));
     printk("A0: %s", temp);
     toHexString(temp, lenOutput, outputData);
     crypto_free_cipher(tfm);
}

void doDESCipherDE(char inpuData[MEM_SIZE], char outputData[MEM_SIZE])
{

     struct crypto_cipher *tfm;
     int numOfCipher, i, j = 0;
     int lenData = strlen(inpuData);
     char temp[MEM_SIZE];
     numOfCipher = (lenData / 8 < 1) ? 1 : (lenData / 8);

     tfm = crypto_alloc_cipher("des", 0, 0);
     crypto_cipher_setkey(tfm, key, 8);
     for (i = 0; i < numOfCipher; i++)
     {
          crypto_cipher_decrypt_one(tfm, &temp[j], &inpuData[j]);
          j += 8;
     }
     strcpy(outputData, temp);
     crypto_free_cipher(tfm);
}

static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off)
{
     char buffer[MEM_SIZE];

     switch (mode)
     {

     case 0:
          memset(plainText, 0, strlen(plainText));
          strcpy(plainText, value);
          printk("Plain Text: |%s|", value);
          sprintf(buffer, "%s", "# Data Inserted successfully");
          break;
     case 1:
          memset(key, 0, strlen(key));
          memset(cipherTextasHex, 0, strlen(plainText));
          strcpy(key, value);
          doDESCipherEN(plainText, cipherTextasHex);
          printk("Cipher Text as Hex: %s", cipherTextasHex);
          sprintf(buffer, "Encrypted Data - DES: %s", cipherTextasHex);
          break;
          break;
     case 2:
          memset(key, 0, strlen(key));
          memset(cipherTextasHex, 0, strlen(plainText));
          strcpy(key, value);
          doAESCipherEN(plainText, cipherTextasHex);
          printk("Cipher Text as Hex: %s", cipherTextasHex);
          sprintf(buffer, "Encrypted Data - AES: %s", cipherTextasHex);
          break;
     case 3:
          memset(key, 0, strlen(key));
          memset(plainText, 0, strlen(plainText));
          memset(cipherText, 0, strlen(cipherText));
          strcpy(key, value);
          hexToUnicode(cipherTextasHex, strlen(cipherTextasHex), cipherText);
          doDESCipherDE(cipherText, plainText);
          printk("Decrypted Data - DES: %s", plainText);
          sprintf(buffer, "Decrypted Data - DES: %s", plainText);
          break;
          break;
     case 4:
          memset(key, 0, strlen(key));
          memset(plainText, 0, strlen(plainText));
          memset(cipherText, 0, strlen(cipherText));
          strcpy(key, value);
          hexToUnicode(cipherTextasHex, strlen(cipherTextasHex), cipherText);
          doAESCipherDE(cipherText, plainText);
          printk("Decrypted Data - AES: %s", plainText);
          sprintf(buffer, "Decrypted Data - AES: %s", plainText);
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
     sscanf(kernel_buffer, "opt:%s\nvalue:%26[^\n]\noptional:%s[^\n]", opt, value, cipherTextasHex);
     kstrtoint(opt, 0, &mode);
     return 0;
}

static int __init char_driver_init(void)
{
     alloc_chrdev_region(&dev_number, 0, 1, "lab08");
     printk("Insert character driver successfully. major(%d), minor(%d)\n", MAJOR(dev_number), MINOR(dev_number));
     device_class = class_create(THIS_MODULE, "lab08");
     device_create(device_class, NULL, dev_number, NULL, "lab8_cipher");

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
