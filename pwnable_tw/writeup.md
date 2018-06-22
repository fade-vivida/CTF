# WriteUp #
# 1. BookWriter #
## 1）利用方式 ##
**Off by null + Hourse of orange**
## 2）漏洞关键代码 ##
**漏洞点1：**  
首先程序在edit\_page函数中存在漏洞。如果申请一个size大小的chunk，且将其全部填满为非空字符时，则在接下来计算chunk的长度时，会将下一个chunk的size字段也计算在内，可以造成多字节溢出（视具体下一个chunk的size值而定，例如：当nextchunk->size=0x2f010时，则可以溢出3个字节）。  
**漏洞点2：**  
在add\_page函数中存在访问越界漏洞。正常情况下page_list数组大小为8，紧接在它后面的时size\_list数组。当在add\_page函数中判断时，由于少加了一个"="号，导致可以申请9个page，且将最后申请的page的地址放在了第一个page的size数组的位置（即size\_list[0]），这样会导致一个对于page\_list[0]的超长写入。  
**漏洞点3：**  
由于Author与page\_list紧邻，因此当填满Author数组时，后泄露其后的page\_list[0]的地址。
## 3）漏洞利用 ##
### 3.1 泄露堆地址 ####
利用漏洞点3可泄漏堆地址
### 3.2 House of Orange ####
House of Orange利用原理就是通过堆溢出漏洞，修改top\_chunk的size字段，然后再次申请一个大于修改后top->size的chunk时，会调用sysmalloc()函数。而sysmalloc会采用两种方式（mmap一块新的内存，或者是对top chunk进行扩展）。  
![sysmalloc]()  
因此，如果申请大小小于mmap\_threshold（即128*1024）,则会对原来的top chunk进行扩展，会将旧的top chunk放入unsortedbin中。  
![int free]()  
### 3.3 Unsortedbin attack ###
Unsortedbin attack的利用思路为，利用对Unsortedbin中chunk进行拆链时，会将victim->bk->fd赋值为&unsortedbin,从而达到对任意地址写固定值。