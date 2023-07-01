### 题目分析

根据题目的防护方式开启情况和IDA反汇编后的题目分析得出，一个明显的栈溢出gets函数，且没有开启canary,也关闭了PIE。可以获得一些函数的地址，文件secure函数中有一个system("shell!?") 函数，虽然这个函数明显是错误的，但可以透露一些信息。函数中还有字符串常量 "/bin/sh"，这很明显可以用来当参数。

![](H:\CVE_download\stack_overflow\ret2libc1\01.PNG)

使用ROP方法，发现文件中并没有足够的gadgets,且文件是动态链接的。此时可以想到上面的system函数可以为我们提供一个plt表项，我们只要返回地址跳转这个表项再传入正确的参数就可以拿到shell。

![](H:\CVE_download\stack_overflow\ret2libc1\02.PNG)

根据函数的调用规则，我们在溢出时需要考虑到函数调用所使用的参数的位置。栈中的顺序应该是，父函数在栈中填入参数，并将返回值压入栈中，子函数先push ebp,保存父函数ebp的值，再执行自己的函数体。从这个过程可以知道，子函数使用参数开始的地址是 ebp + 两个字的长度。由此来构造栈溢出。返回值填入system@plt的地址0x8048460 就可以通过got跳转到system,且在解析过程中也会保持栈平衡。

![](H:\CVE_download\stack_overflow\ret2libc1\03.PNG)

最终的攻击payload

![](H:\CVE_download\stack_overflow\ret2libc1\04.PNG)

总结，这个小案例最大的收获弄懂动态链接的过程，最关键的是.plt和.got.plt。在Partial RELRO保护下GOT表具有可写权限，可以通过修改GOT表做一些操作，但在开启Full RELRO保护下，GOT表的条目在启动后都被动态链接器填充并设置为只读，不能修改。在本例中确实也没有修改GOT表。但需要在plt表中有相应的条目。