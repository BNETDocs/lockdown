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

#ifndef __LOCKDOWNSHA1_H__
#define __LOCKDOWNSHA1_H__

/* For my heap definition. */
#include "Lockdown.h"

typedef struct
{
	int bitlen[2];
	int state[32];
} real_LD_SHA1_CTX;

/* This has to be called exactly once. I don't check for it. */
void real_sha1_initialize();

void real_sha1_tweedle(int *ptr_rotator, int bitwise, int bitwise2, int bitwise3, int *ptr_adder, int *ptr_ret);
void real_sha1_twitter(int *ptr_rotator, int bitwise, int rotator2, int bitwise2, int *ptr_rotator3, int *ptr_ret);
void real_sha1_init(real_LD_SHA1_CTX *ctx);
void real_sha1_update(real_LD_SHA1_CTX *ctx, char *data, int len);
void real_sha1_final(real_LD_SHA1_CTX *ctx, char *buffer);
void real_sha1_transform(int *data, int *state);

int DecodeModule(HMODULE storm, int num);

BOOL real_shuffle_value_string(char *str, int len, char *buffer);
void real_word_shifter(short *str1, short *str2);
int real_string_combine(char *buf1,int *length,char *buf2);

int real_number_compare_deprecated(int *num1, int *num2);

int real_process_reloc(t_lockdown_heap *lockdown_heap, void *baseaddr, BOOL is32bit, void *reloc_section);
int real_process_import(t_lockdown_heap *lockdown_heap, void *baseaddr, void *import_sectionoffset,void *import_sectionsize,BOOL is32Bit, void *importsection);
void real_ArrangeRecords(void *record1, void *record2);
void real_ldheap_sort(char *heapdata, int heaplength);

void real_AddZeroes(LD_SHA1_CTX *sha1, int amount);
BOOL real_hash1(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, void *baseaddr, void *preferred_baseaddr, int reserved_for_64bit, void *section_ptr, int section_alignment);
BOOL real_hash2(void *addr_baseaddr, void *preferred_baseaddr, int reserved_for_64bit, LD_SHA1_CTX *ctx, int *offset_memory, void *ptr_memory);
void real_hash_file(LD_SHA1_CTX *ctx, void *baseaddr);


void real_AddTolockdown_heap(char *data, t_lockdown_heap *lockdown_heap);


#endif