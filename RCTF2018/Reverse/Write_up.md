# RCTF2018 #
## Reverse ##
### Simple\_vm ###
题目分析：一道虚拟机逆向的题目，给出了一个p.bin文件，包含了操作的指令序列和输出数据。要求通过对程序执行流程进行分析，从输出数据得到正确的用户输入。

程序功能分析如下：
#### 1.输出"Input Flag:"，提示用户输入Flag ####
执行流程：</br>
**case 0x01：**</br>
以该指令之后4个字节作为偏移（offset），跳转到file+offset处继续执行（ip = file + offset）。</br>
**case 0x15：**</br>
设置当天tmp值为之后4个字节，然后ip=ip+4。</br>
**case 0x0e:**</br>
tmp = tmp + 1</br>
**case 0x12**:</br>
将tmp的值赋值给c，c = tmp</br>
**case 0x0B:**</br>
以变量c为地址，调用putchar()函数输出一个字符，putchar(c)。</br>
**case 0x0C:**</br>
以该指令后4个字节(ip+1~ip+4)为地址偏移（offset），判断该地址处byte是否为0（实际保存要输出字符串的长度）。如果不为0，则\*（file+offset）=\*（file+offset）- 1，长度减1操作。并跳转到\*(ip+5)处继续执行（其实会再次调用case 0xe，一直到输出完所有字符）,然后跳转到\*(ip+8)处执行。  </br>
最终调用序列如下所示：</br>
**case 0x01 --> case 0x15 --> case 0x0e --> case 0x12 --> case 0x0B --> case 0x0C --> case 0x0e --> case 0x0B --> case 0x0C（循环）</br>**
构成一个调用循环，出循环条件为已经打印完字符串</br>

#### 2.读取用户输入input ####
**case 0x15:</br>**
设置当前tmp值为之后4个字节，然后ip=ip+4。</br>
**case 0x0e:</br>**
tmp = tmp + 1</br>
**case 0x0A:</br>**
调用getchar()读取一个字符，然后将该值赋值给变量c。</br>
**case 0x16:</br>**
以tmp为地址，将c写到tmp处，file[tmp] = c。</br>
**case 0x0C:</br>**
与之前分析相同，读取长度值。判断是否已读完所有内容。</br>
最终调用序列如下所示：</br>
**case 0x15 --> case 0x0e --> case 0x0a --> case 0x16 -->case 0x0c --> case 0x0e -- 0x0a(循环）**

#### 3.对输入input的每个字节进行变换 ####
**case 0x03:</br>**
以之后4个字节内容为地址，取值后赋值给变量c, c = file[offset]</br>
**case 0x10:</br>**
将c的值赋值给tmp，tmp = c。</br>
**case 0x11:</br>**
以当前指令后4个字节为地址偏移，取值后加给变量c, c += file[offset]</br>
**case 0x13:</br>**
以c为偏移，取值再赋值给c，c = file[c]。</br>
**case 0x04:</br>**
以当前指令后4个字节为地址偏移，将c的值写到该处，file[offset] = c。</br>
**case 0x08:</br>**
关键操作，c = ~(tmp&c)。</br>
**case 0x04:</br>**
同上。</br>
**case 0x10:</br>**
同上。</br>
**case 0x03:</br>**
同上。</br>
**case 0x08:</br>**
同上。</br>
**case 0x04:</br>**
同上。</br>
之后调用序列如下：</br>
**case 0x03 --> case 0x03 --> case 0x08 --> case 0x10 -- case 0x03 --> case 0x08 --> case 0x04。**</br>
归纳其变换操作如下所示：</br>

    c = input[i]</br>
    tmp = file[0x140]  
    c = ~(c&tmp)  
    tmp = c  
    c = file[0x140]  
    c = ~(c&tmp)  
    ttmp = c  
    c = input[i]  
    c = ~(c&tmp)  
    tmp = c  
    c = ttmp  
    input[i] = ~(c&tmp)  
对改变换进行化简，消除中间变量，可得  

    input[i] = (~input[i]&file[0x140]) | (input[i]&~file[0x140])
	input[i] = input[i] ^ file[0x140]

之后调用序列为：  
**case 0x03：**   
c = file[0x140]  
**case 0x11:**  
c = 0xf1 + c(实际为定位到input[i]所在位置）  
**case 0x10:**   
tmp = c,tmp保存input[i]地址，即tmp = &input[i]  
**case 0x03:**  
c = file[0x144]，c保存最终变换结果。  
**case 0x16：**   
file[tmp] = c，即将变换后结果写回input[i]。  
**case 0x05：**  
tmp = file[0x140]  
**case 0x0e:**  
tmp = tmp + 1  
**case 0x06:**  
file[0x140] = tmp  
**case 0x0c:**  
判断是否处理完所有输入，判断长度为file[0x145]处的值。若file[0x145]不为0，则继续处理剩余输入。  


#### 4.对输入input进行Check ####
**case 0x03:**  
c = file[0x146] = 0x1f  
**case 0x11:**  
c = c + 0x05 = 0x24  
**case 0x13:**  
c = file[c]  
**case 0x10:**  
tmp = c  
**case 0x03:**  
c = file[0x146] = 0x1f  
**case 0x11:**  
c = c + 0x111 = 0x130  
**case 0x13:**  
c = file[c]，取输入的最后一个字符，c = input[len-1]。  
**case 0x17:**  
fl = c - tmp  
**case 0x18:**  
判断fl是否为0，也即判断input[len-1] == file[0x24]是否相等。如果相等，则跳转到case 0x0c处。相当于倒序比较变换后的输入与文件中某个固定的字符序列是否相同。若成功，输出“Rigth”，否则输出“Wrong”。  

#### 5.最终Flag ####
![Aaron Swartz](https://raw.githubusercontent.com/fade-vivida/picture/master/RCTF2018/Reverse/Simple_vm/picture/1.png)
