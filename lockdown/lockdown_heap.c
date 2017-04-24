/* Copyright (c) 2007 x86

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE. */

#include "lockdown_heap.h"

t_lockdown_heap *ldheap_create()
{
	t_lockdown_heap *newheap = (t_lockdown_heap *) malloc(sizeof(t_lockdown_heap));
	newheap->memory = HeapAlloc(GetProcessHeap(), 0, 0x1000);
	newheap->currentlength = 0;
	newheap->maximumlength = 0x100;

	return newheap;
}

void ldheap_destroy(t_lockdown_heap *lockdown_heap)
{
	//HeapFree(GetProcessHeap(), 0, lockdown_heap->memory);
}


void ldheap_print(t_lockdown_heap *lockdown_heap)
{
	int i;
	int j;

	for(i = 0; i < lockdown_heap->currentlength; i++)
	{
		/* Since the length is in 0x10-byte blocks, we can print off 0x10 at a time */
		for(j = 0; j < 0x10; j++)
		{
			unsigned char c = lockdown_heap->memory[(i * 0x10) + j];
			printf("%02x ", c);
		}

		printf("\t");

		for(j = 0; j < 0x10; j++)
		{
			unsigned char c = lockdown_heap->memory[(i * 0x10) + j];
			printf("%c", (c < 0x20 || c > 0x7F) ? '.' : c);
		}	
		printf("\n");
	}
	printf("Length: %d bytes\n\n", lockdown_heap->currentlength * 0x10);
}

BOOL ldheap_compare(t_lockdown_heap *heap1, t_lockdown_heap *heap2)
{
	int i;

	if(heap1->currentlength != heap2->currentlength)
		return FALSE;

	for(i = 0; i < heap2->currentlength; i++)
	{
		if(memcmp(heap1->memory + (i * 0x10), heap2->memory + (i * 0x10), 0x10))
		{
			int *failed1 = (int*) (heap1->memory + (i * 0x10));
			int *failed2 = (int*) (heap2->memory + (i * 0x10));
			printf("Compare failed at record %08x\n", i);
			printf(" %08x %08x %08x %08x\n", failed1[0], failed1[1], failed1[2], failed1[3]);
			printf(" %08x %08x %08x %08x\n", failed2[0], failed2[1], failed2[2], failed2[3]);
			printf("\n");

			printf("Previous records:\n");
			printf(" %08x %08x %08x %08x\n", failed1[-4], failed1[-3], failed1[-2], failed1[-1]);
			printf(" %08x %08x %08x %08x\n", failed2[-4], failed2[-3], failed2[-2], failed2[-1]);
			printf("\n");

			printf("Next records:\n");
			printf(" %08x %08x %08x %08x\n", failed1[4], failed1[5], failed1[6], failed1[7]);
			printf(" %08x %08x %08x %08x\n", failed2[4], failed2[5], failed2[6], failed2[7]);
			printf("\n");

			return FALSE;
		}
	}

	return TRUE;
}

void ldheap_add(t_lockdown_heap *lockdown_heap, char *data)
{
	if(lockdown_heap->currentlength + 0x10 >= lockdown_heap->maximumlength)
	{
		lockdown_heap->maximumlength = lockdown_heap->maximumlength * 2;
		lockdown_heap->memory = HeapReAlloc(GetProcessHeap(), 0, lockdown_heap->memory, lockdown_heap->maximumlength * 0x10);
	}
	memcpy(lockdown_heap->memory + (lockdown_heap->currentlength * 0x10), data, 0x10);
	lockdown_heap->currentlength = lockdown_heap->currentlength + 1;
}

static int sortfunc(const void *record1, const void *record2)
{
	int *a = (int *) record1;
	int *b = (int *) record2;

	if(a[0] < b[0])
		return -1;
	else if(a[0] > b[0])
		return 1;

	return 0;
}


void ldheap_sort(t_lockdown_heap *lockdown_heap)
{
//	int numelements = 1 + (((int)record2 - (int)record1) / 0x10);
//	qsort(record1, numelements, 0x10, sortfunc);
 	qsort(lockdown_heap->memory, lockdown_heap->currentlength, 0x10, sortfunc); 
}
