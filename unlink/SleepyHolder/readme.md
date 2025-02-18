## step1

和前一个`SecretHolder`相似，在这个基础上只能申请一次hugebin，考虑使用fastbin_dup_attack，先申请一块chunk，然后通过把它放入到smallbin的时候修改inuse位，达到攻击目的，伪造chunk。然后进行unlink。



## step2

unlink发生后bss变为默认状态，首先修改[free@got.plt](mailto:free@got.plt)的值为puts@plt，接下来修改*big_ptr的值为puts_got，然后泄露出libcbase。



## step3

将puts的got表地址改为one_gadget地址。



## Difficulty

3