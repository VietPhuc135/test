CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_ALL=n

obj-m := lab.o
ccflags-y := -Wframe-larger-than=4096

default:clean
	gcc test.c -o test.out -pthread
	gcc server.c -o server.out -pthread
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	
clean:	
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean