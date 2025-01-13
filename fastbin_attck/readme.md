## step1

通过fastbin_dup来完成堆叠的发生，申请4块0x20的chunk和一块0x90的chunk，释放0，1，修改fd指向0x90，然后修改最后一块chunk的大小，来通过申请得到堆叠。



## step2

重新修改size，通过unsorted bin attack，泄露libcbase。



## step3

再次使用fastbin_dup来修改__malloc_hook地址。

## difficult
2
