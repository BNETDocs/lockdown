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

#ifndef __LOCKDOWN_HEAP_H__
#define __LOCKDOWN_HEAP_H__

/* Lockdown stores lists of offsets or addresses in some heap memory that automatically grows. 
 * I've decided to refer to this as the "lockdown heap". Although it's not a heap in the actual
 * sense of the word, or any sense for that matter, it was the best word I icould think of at 
 * the time, and it kinda stuck with me. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>

typedef struct
{
	char *memory;
	int currentlength;
	int maximumlength;
} t_lockdown_heap;

t_lockdown_heap *ldheap_create();
void ldheap_destroy(t_lockdown_heap *lockdown_heap);
void ldheap_print(t_lockdown_heap *lockdown_heap);
BOOL ldheap_compare(t_lockdown_heap *heap1, t_lockdown_heap *heap2);
void ldheap_add(t_lockdown_heap *lockdown_heap, char *data);
void ldheap_sort(t_lockdown_heap *lockdown_heap);


#endif