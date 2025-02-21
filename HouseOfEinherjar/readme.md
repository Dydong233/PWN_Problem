## step1

泄露出libc的地址



## step2

在tinypad处伪造chunk，同时修改各个字节内容，释放后达成house of einherjar攻击。



## step3

通过environ泄露栈上地址，然后将main函数的返回地址改为one_gadget地址。



## Difficulty

3