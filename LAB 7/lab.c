#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/hash.h>
#include <crypto/algapi.h>

#define DRIVER_AUTHOR "tuananh"
#define MEM_SIZE 1024
#define MD5_LEN 16
#define SHA1_LEN 20
#define SHA2_LEN 32

char opt[1], username[100], password[MEM_SIZE];
static int mode;
dev_t dev_number = 0;
static struct class *device_class;
static struct cdev *cdev;
uint8_t *kernel_buffer;

static int driver_open(struct inode *inode, struct file *flip);
static int driver_release(struct inode *inode, struct file *filp);
static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off);
static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off);
void reAssignValue(int size, u8 hashdata[]);
static struct file_operations fops =
    {
        .owner = THIS_MODULE,
        .read = driver_read,
        .write = driver_write,
        .open = driver_open,
        .release = driver_release,
};

struct sdesc
{
     struct shash_desc shash;
     char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
     struct sdesc *sdesc;
     int size;

     size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
     sdesc = kmalloc(size, GFP_KERNEL);
     if (!sdesc)
          return ERR_PTR(-ENOMEM);
     sdesc->shash.tfm = alg;
     return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
                     const unsigned char *data, unsigned int datalen,
                     unsigned char *digest)
{
     struct sdesc *sdesc;
     int ret;

     sdesc = init_sdesc(alg);
     if (IS_ERR(sdesc))
     {
          pr_info("Can't alloc sdesc\n");
          return PTR_ERR(sdesc);
     }

     ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
     kfree(sdesc);
     return ret;
}

static int doHash(char *mode, const unsigned char *data, unsigned int datalen,
                  unsigned char *digest)
{
     struct crypto_shash *alg;
     const char *hash_alg_name = mode;
     int ret;

     alg = crypto_alloc_shash(hash_alg_name, 0, 0);
     if (IS_ERR(alg))
     {
          pr_info("Can't alloc alg %s\n", hash_alg_name);
          return PTR_ERR(alg);
     }
     ret = calc_hash(alg, data, datalen, digest);
     crypto_free_shash(alg);
     return ret;
}

void reAssignValue(int size, unsigned char *hashdata)
{
     size_t i;
     memset(password, 0, sizeof(password));
     for (i = 0; i < size; ++i)
     {
          snprintf(password + strlen(password), 3, "%02x", hashdata[i]);
     }
}

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
     u8 md5[MD5_LEN];
     u8 sha1[SHA1_LEN];
     u8 sha2[SHA2_LEN];

     switch (mode)
     {
     case 1:
          doHash("md5", password, sizeof(unsigned char) * 4, md5);
          reAssignValue(MD5_LEN, md5);
          sprintf(buffer, "%s", password);
          break;
     case 2:
          doHash("sha1", password, sizeof(unsigned char) * 4, sha1);
          reAssignValue(SHA1_LEN, sha1);
          sprintf(buffer, "%s", password);
          break;
     case 3:
          doHash("sha256", password, sizeof(unsigned char) * 4, sha2);
          reAssignValue(SHA2_LEN, sha2);
          sprintf(buffer, "%s", password);
          break;
     default:
          doHash("md5", password, sizeof(unsigned char) * 4, md5);
          doHash("sha1", password, sizeof(unsigned char) * 4, sha1);
          doHash("sha256", password, sizeof(unsigned char) * 4, sha2);
          reAssignValue(MD5_LEN, md5);
          sprintf(buffer, "%s", password);
          reAssignValue(SHA1_LEN, sha1);
          printk("%s", password);
          sprintf(buffer + strlen(buffer), " %s", password);
          reAssignValue(SHA2_LEN, sha2);
          sprintf(buffer + strlen(buffer), " %s", password);
          sprintf(buffer + strlen(buffer), " %s\n", username);
          break;
     }

     copy_to_user(user_buf, buffer, MEM_SIZE);
     return 0;
}

static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off)
{
     copy_from_user(kernel_buffer, user_buf, len);
     memset(opt, 0, sizeof(opt));
     memset(username, 0, sizeof(username));
     memset(password, 0, sizeof(password));
     sscanf(kernel_buffer, "opt:%s\nusername:%s\npassword:%s", opt, username, password);
     kstrtoint(opt, 0, &mode);
     return 0;
}

static int __init char_driver_init(void)
{
     alloc_chrdev_region(&dev_number, 0, 1, "lab07");
     printk("Insert character driver successfully. major(%d), minor(%d)\n", MAJOR(dev_number), MINOR(dev_number));

     device_class = class_create(THIS_MODULE, "lab07");
     device_create(device_class, NULL, dev_number, NULL, "lab7_hash");

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
