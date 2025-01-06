## step1

通过author name进行溢出泄露heap的地址，因为刚好存在off-by-null。



## step2

通过mmap进行申请chunk使得chunk_control2在chunk_control1之后，制造一块fake chunk，再次通过off-by-null进行修改，泄露mmap的地址来推断出libcbase(但是本地调试一直都是一个随机的数，不是固定的，不知道是不是aslr的原因)。

## step3

控制chunk_control1写入free_hook地址，然后控制chunk_control2写入one_gadget