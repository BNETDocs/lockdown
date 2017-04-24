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

#include <windows.h>

#include "real_Lockdown.h"

static HMODULE ix86;
static HMODULE storm;
static HMODULE battle;

static void *addr_tweedle;
static void *addr_twitter; 
static void *addr_sha1init;
static void *addr_sha1update;
static void *addr_sha1final;
static void *addr_sha1transform;
static void *addr_sha1updatewrapper;

static void *addr_calcvaluestring;
static void *addr_addrdecode;
static void *addr_checkrevision;
static void *addr_real_word_shifter;
static void *addr_string_combine;

static void *addr_number_compare_deprecated;
static void *addr_noname;

static void *addr_processreloc;
static void *addr_processimport;
static void *addr_arrangerecords;
static void *addr_ldheap_sort;

static void *addr_ld_sha1_pad;
static void *addr_hash1;
static void *addr_hash2;
static void *addr_hash_file;

static void *addr_addtoheap;

void real_sha1_initialize()
{
	ix86 = LoadLibrary("c:\\temp\\lockdown-IX86-00.dll");
	storm = LoadLibrary("C:\\program files\\starcraft\\storm.dll");
	battle = LoadLibrary("C:\\program files\\starcraft\\battle.snp");

	addr_tweedle           = (void*) ((int) ix86 + 0x232e);
	addr_twitter           = (void*) ((int) ix86 + 0x2365);
	addr_sha1init          = (void*) ((int) ix86 + 0x2731);
	addr_sha1update        = (void*) ((int) ix86 + 0x275C);
	addr_sha1final         = (void*) ((int) ix86 + 0x27E8);
	addr_sha1transform     = (void*) ((int) ix86 + 0x2396);
	addr_sha1updatewrapper = (void*) ((int) ix86 + 0x2317);

	addr_calcvaluestring   = (void*) ((int) ix86 + 0x116D);
	addr_addrdecode        = (void*) ((int) ix86 + 0x110E);
	addr_real_word_shifter       = (void*) ((int) ix86 + 0x14D9);
	addr_string_combine     = (void*) ((int) ix86 + 0x1000);

	addr_number_compare_deprecated     = (void*) ((int) ix86 + 0x1C8C);
	addr_noname            = (void*) ((int) ix86 + 0x1A40);

	addr_processreloc      = (void*) ((int) ix86 + 0x1DFD);
	addr_processimport     = (void*) ((int) ix86 + 0x1D15);
	addr_arrangerecords    = (void*) ((int) ix86 + 0x1A40);
	addr_ldheap_sort      = (void*) ((int) ix86 + 0x1540);

	addr_ld_sha1_pad         = (void*) ((int) ix86 + 0x1CA8);
	addr_hash1             = (void*) ((int) ix86 + 0x1F84);
	addr_hash2             = (void*) ((int) ix86 + 0x1E98);
	addr_hash_file            = (void*) ((int) ix86 + 0x2167);

	addr_addtoheap         = (void*) ((int) ix86 + 0x1C3D);

	addr_checkrevision     = GetProcAddress(ix86, "CheckRevision");

	*((HANDLE*)(ix86 + 0x433c)) = GetProcessHeap();
}

void real_sha1_tweedle(int *ptr_rotator, int bitwise, int bitwise2, int bitwise3, int *ptr_adder, int *ptr_ret)
{
	__asm
	{
		mov ecx, bitwise3
		mov edx, ptr_adder
		mov esi, ptr_ret
		push bitwise2
		push bitwise
		push ptr_rotator
		call addr_tweedle
		add esp, 0x0c
	}
}

void real_sha1_twitter(int *ptr_rotator, int bitwise, int rotator2, int bitwise2, int *ptr_rotator3, int *ptr_ret)
{
	__asm
	{
		mov eax, rotator2
		mov edx, bitwise2
		mov esi, ptr_rotator3
		mov edi, ptr_ret
		push bitwise
		push ptr_rotator
		call addr_twitter
		add esp, 0x08
	}
}

void real_sha1_init(real_LD_SHA1_CTX *ctx)
{
	__asm
	{
		mov eax, ctx
		call addr_sha1init
	}
}

void real_sha1_update(real_LD_SHA1_CTX *ctx, char *data, int len)
{
	__asm
	{
		mov eax, data
		mov esi, ctx
		push len
//		int 3
		call addr_sha1update
	}
}

void real_sha1_final(real_LD_SHA1_CTX *ctx, char *buffer)
{
	__asm
	{
		mov ecx, ctx
		mov edi, buffer
//		int 3
		call addr_sha1final
	}
}

void real_sha1_transform(int *data, int *state)
{
	__asm
	{
		mov eax, data
		push state
		call addr_sha1transform
		add esp, 4
	}
}

BOOL real_shuffle_value_string(char *strn, int len, char *buffer)
{
	int retval;
	__asm
	{
		push len
		push strn
		mov esi, buffer
		//int 3
		call addr_calcvaluestring;
		add esp, 8
		mov retval, eax
	}

	return retval;
}

void real_word_shifter(short *str1,short *str2)
{
	__asm
	{
		mov ecx, str1
		mov edx, str2
		call addr_real_word_shifter
	}
}

int real_string_combine(char *buf1,int *lngth,char *buf2)
{
	int retval;
	__asm
	{
		push buf2
		push lngth
		push buf1
		call addr_string_combine
		add esp, 0x0c
		mov retval, eax
	}

	return retval;
}

int real_number_compare_deprecated(int *num1, int *num2)
{
	int retval;
	__asm
	{
		push num2
		push num1
		call addr_number_compare_deprecated
		add esp, 8

		mov retval, eax
	}

	return retval;
}

int real_process_reloc(t_lockdown_heap *lockdown_heap, void *baseaddr, BOOL is32bit, void *reloc_section)
{
	__asm
	{
		push is32bit
		push baseaddr
		push lockdown_heap
		mov ecx, reloc_section
		call addr_processreloc
		add esp, 0x0C
	}
}

int real_process_import(t_lockdown_heap *lockdown_heap, void *baseaddr, void *import_sectionoffset,void *import_sectionsize,BOOL is32Bit, void *importsection)
{
	__asm
	{
		push is32Bit
		push import_sectionsize
		push import_sectionoffset
		push baseaddr
		push lockdown_heap
		mov eax, importsection
		call addr_processimport 
		add esp, 0x14
	}
}

void real_ArrangeRecords(void *record1, void *record2)
{
	__asm
	{
		push addr_number_compare_deprecated
		push record1
		mov eax, record2

		call addr_arrangerecords

		add esp, 8
	}
}

void real_ldheap_sort(char *heapdata, int heaplength)
{
	__asm
	{
		push addr_number_compare_deprecated
		mov eax, heaplength
		mov ecx, heapdata
		
		call addr_ldheap_sort

		add esp, 4
	}
}

void real_AddTolockdown_heap(char *data, t_lockdown_heap *lockdown_heap)
{
	__asm
	{
		pushad ; Because ebx is being modified, preserving registers is probably a good idea

		push data
		mov ebx, lockdown_heap
		call addr_addtoheap

		popad
	}
}

void real_ld_sha1_pad(LD_SHA1_CTX *ctx, int amount)
{
	int *sha1class = malloc(sizeof(int) * 2);

	sha1class[0] = (int) &addr_sha1updatewrapper;
	sha1class[1] = (int) ctx;

	__asm
	{
		pushad

		mov ecx, amount
		mov edi, sha1class
		call addr_ld_sha1_pad

		popad
	}

	free(sha1class);
}

BOOL real_hash1(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, void *baseaddr, void *preferred_baseaddr, int reserved_for_64bit, void *section_ptr, int section_alignment)
{
	BOOL retval;
	int *sha1class = malloc(sizeof(int) * 2);

	sha1class[0] = (int) &addr_sha1updatewrapper;
	sha1class[1] = (int) ctx;

	__asm
	{
		push reserved_for_64bit
		push preferred_baseaddr
		push baseaddr
		push lockdown_heap
		push sha1class
		mov eax, section_ptr
		mov ecx, section_alignment
//int 3
		call addr_hash1
		mov retval, eax

		add esp, 0x14
	}

	free(sha1class);

	return retval;
}

BOOL real_hash2(void *addr_baseaddr, void *preferred_baseaddr, int reserved_for_64bit, LD_SHA1_CTX *ctx, int *offset_memory, void *ptr_memory)
{
	int *sha1class = malloc(sizeof(int) * 2);
	BOOL retval;

	sha1class[0] = (int) &addr_sha1updatewrapper;
	sha1class[1] = (int) ctx;

	__asm
	{
		pushad

		push reserved_for_64bit
		push preferred_baseaddr
		push addr_baseaddr
		mov eax, sha1class
		mov ecx, offset_memory
		mov esi, ptr_memory

//		int 3
		call addr_hash2
		mov retval, eax

		add esp, 0x0c

		popad
	}

	free(sha1class);

	return retval;
}

void real_hash_file(LD_SHA1_CTX *ctx, void *baseaddr)
{
		int *sha1class = malloc(sizeof(int) * 2);

	sha1class[0] = (int) &addr_sha1updatewrapper;
	sha1class[1] = (int) ctx;

	__asm
	{
		push baseaddr
		push sha1class
		mov eax, baseaddr

//		int 3

		call addr_hash_file

		add esp, 8
	}

	free(sha1class);
}