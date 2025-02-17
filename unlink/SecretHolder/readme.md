## step1

源程序中存在UAF，造成堆叠然后进行篡改内容，伪造一块chunk，然后进行释放来进行unlink。

## step2

unlink发生后bss变为默认状态，首先修改free@got.plt的值为puts@plt，接下来修改*big_ptr的值为puts_got，然后泄露出libcbase。

## step3

将puts的got表地址改为one_gadget地址。

## Difficulty

3