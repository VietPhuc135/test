cmd_/home/anh/LINUX/LABVI/lab.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id  -T ./scripts/module-common.lds -o /home/anh/LINUX/LABVI/lab.ko /home/anh/LINUX/LABVI/lab.o /home/anh/LINUX/LABVI/lab.mod.o;  true