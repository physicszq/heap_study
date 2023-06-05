#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void main() {
	// reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8
	void *ptr[7];
	for(int i = 0; i < 7; i++)
		ptr[i] = malloc(0x40);
	for(int i = 0; i < 7; i++)
		free(ptr[i]);
	void* p1 = calloc(1,0x40);
  free(p1);
  void* p3 = malloc(0x400);
	assert(p1 == p3);
  printf("Triggering the double free vulnerability!\n\n");
	free(p1);
	void *p4 = malloc(0x400);
	assert(p4 == p3);

	printf("The double free added the chunk referenced by p1 \n");
	printf("to the tcache thus the next similar-size malloc will\n");
	printf("point to p3: p3=%p, p4=%p\n\n",p3, p4);
}
