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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>
#include <winnt.h>

#include "seed_finder.h"
#include "Lockdown.h"
#include "real_Lockdown.h"
#include "lockdown_heap.h"
#include "lockdown_sha1.h"

/** Prepares the value string, which is basically a seed sent by Battle.net, to 
 ( be used in the hash. */
static BOOL shuffle_value_string(unsigned char *str, int len, unsigned char *buffer);

/** Completely hashes a single file. This involves loading it into memory, processing
 * the header, and adding all its memory to a hash. */
static int hash_file(LD_SHA1_CTX *ctx, void *baseaddr, char *lockdown);
/** Processes (I think) the relocation section of the PE's header, adding important
 * entries to the lockdown_heap. */
static int process_reloc(t_lockdown_heap *lockdown_heap, void *baseaddr, BOOL is32bit, void *reloc_section);
/** Processes (I think( the imports section of the PE's header, adding important entries
 * to the lockdown_heap. */
static int process_import(t_lockdown_heap *lockdown_heap, void *baseaddr, void *import_sectionoffset, int import_sectionsize, BOOL is32Bit, void *importsection);
/** Do the overall hash of the file, based on the list of addresses/offsets generated
 * by the process_import and process_reloc functions. */
static BOOL hash1(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, char *baseaddr, void *preferred_baseaddr, int preferred_baseaddr_upper, int *section_ptr, int section_alignment, char *lockdown);
/** Down and dirty, hash the actual addresses. Works perfectly for 32-bit files, but is 
 * untested on 16- and 64-bit files. */
static BOOL hash2(char *addr_baseaddr, char *preferred_baseaddr, int preferred_baseaddr_upper, LD_SHA1_CTX *ctx, int *offset_memory, int *ptr_memory, char *lockdown);

/** At first, I thought this combined the two strings, where is where I got the name from. 
 * As it turns out, it just moves one string to the other, processing it on the way. */
static int string_combine(char *str1, int *length, char *str2);
/** Shifts around a bunch of words for the string_combine function. I'm awfully glad
 * that the programmer didn't think to use "inline" for this. */
static void word_shifter(unsigned short *str1, unsigned short *str2);

/** This was used in some old calculations, but was replaced with something that
 * actually made sense. I'm keeping it around for sentimental reasons. */
static int number_compare_deprecated(int *num1, int *num2);


BOOL CheckRevision(char *valuestring, char *lockdownfile, int *out_hashbuf1, char out_hashbuf2[0x11], char *imagedump, char *path_file1, char *path_file2, char *path_file3)
{
	LD_SHA1_CTX ctx;
	int return_is_valid = 1;
	int module_offset = 0x400000 - 0x400000; 

	char ld_sha1_out_buffer_1[0x14];
	char ld_sha1_out_buffer_2[0x14];
	int length_valuestring = strlen(valuestring);
	char valuestring_encoded[0x10];

	char valuestring_buffer_1[0x40];
	char valuestring_buffer_2[0x40];

	char temp_memory[0x10];

	int i;

	HMODULE lockdown  = LoadLibrary(lockdownfile);
	HMODULE file1;
	HMODULE file2;
	HMODULE file3;

	if(!lockdown)
	{
		printf("Couldn't load lockdown file: %s\n", lockdownfile);
		return FALSE;
	}

	file1 = LoadLibrary(path_file1);
	if(!file1)
	{
		printf("Couldn't load %s\n", path_file1);
		return FALSE;
	}

	file2 = LoadLibrary(path_file2);
	if(!file2)
	{
		printf("Couldn't load %s\n", path_file2);
		FreeLibrary(file1);
		return FALSE;
	}

	file3 = LoadLibrary(path_file3);
	if(!file3)
	{
		printf("Couldn't load %s\n", path_file3);
		FreeLibrary(file1);
		FreeLibrary(file2);
		return FALSE;
	}

	shuffle_value_string(valuestring, length_valuestring, valuestring_encoded);

	RtlFillMemory(valuestring_buffer_1, 0x40, '6');
	RtlFillMemory(valuestring_buffer_2, 0x40, '\\');

	for(i = 0; i < 0x10; i++)
	{
		valuestring_buffer_1[i] = valuestring_buffer_1[i] ^ valuestring_encoded[i];
		valuestring_buffer_2[i] = valuestring_buffer_2[i] ^ valuestring_encoded[i];
	}

	ld_sha1_init(&ctx);
	ld_sha1_update(&ctx, valuestring_buffer_1, 0x40);

	hash_file(&ctx, (char*)lockdown, lockdownfile);
	hash_file(&ctx, (char*)file1, lockdownfile);
	hash_file(&ctx, (char*)file2, lockdownfile);
	hash_file(&ctx, (char*)file3, lockdownfile);
	ld_sha1_hash_file(&ctx, imagedump);
	ld_sha1_update(&ctx, (char*)&return_is_valid, 4); /* Used to verify return address */
	ld_sha1_update(&ctx, (char*)&module_offset, 4); /* Used to verify the module */
	ld_sha1_final(&ctx, (int*)ld_sha1_out_buffer_1);

	ld_sha1_init(&ctx);
	ld_sha1_update(&ctx, (char*)valuestring_buffer_2, 0x40);
	ld_sha1_update(&ctx, (char*)ld_sha1_out_buffer_1, 0x14);
	ld_sha1_final(&ctx, (int*)ld_sha1_out_buffer_2);

	RtlMoveMemory(out_hashbuf1, ld_sha1_out_buffer_2, 4);
	RtlMoveMemory(temp_memory, ld_sha1_out_buffer_2 + 4, 0x10);

	length_valuestring = 0xFF;
	string_combine(out_hashbuf2, &length_valuestring, temp_memory);

	/* Note: Freeing files in order is very important. */
	FreeLibrary(file1);
	FreeLibrary(file2);
	FreeLibrary(file3);
	FreeLibrary(lockdown);

	return TRUE;
}

BOOL shuffle_value_string(unsigned char *str, int len, unsigned char *buffer)
{
	int pos;
	int i;
	unsigned char adder;
	unsigned char shifter;

	pos = 0;

	while(len)
	{
		shifter = 0;
		
		for(i = 0; i < pos; i++)
		{
			unsigned char b = buffer[i];
			buffer[i] = -buffer[i] + shifter;
			shifter = ((((b << 8) - b) + shifter) >> 8);
		}

		if(shifter)
		{
			if(pos >= 0x10)
				return 0;

			buffer[pos++] = shifter;
		}

		adder = str[len - 1] - 1;
		for(i = 0; i < pos && adder; i++)
		{
			buffer[i] = buffer[i] + adder;
			adder = buffer[i] < adder;
		}
		
		if(adder)
		{
			if(pos >= 0x10)
				return 0;

			buffer[pos++] = adder;
		}

		len--;
	}

	/* Fills whatever's left in the buffer with 0. */
	RtlFillMemory(buffer + pos, 0x10 - pos, 0);

	return 1;
}


int hash_file(LD_SHA1_CTX *ctx, char *baseaddr, char *lockdown)
{
	int eax, ecx, edx;
	void *esi;
	void *PEImageBaseUpper;
	void *PEImageBase;
	int PESectionAlignment;
	int is32bit;
	char *DataDirectory_Imports;
	char *DataDirectory_Reloc;
	IMAGE_DOS_HEADER *dosheader = (IMAGE_DOS_HEADER *) baseaddr;
	IMAGE_NT_HEADERS *ntheader = (IMAGE_NT_HEADERS *) (baseaddr + dosheader->e_lfanew);
	IMAGE_DATA_DIRECTORY *dir1, *dir2;
	int i;

	

	t_lockdown_heap *lockdown_heap = ldheap_create();

	eax = (int) baseaddr;
	esi = *((char**)(baseaddr + 0x3c));
	esi = (void*)(((int)esi) + eax);


	/* Verifies that this is actually a pe file, by comparing it to "PE\0\0" */
	if(ntheader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	eax = *((int*)((int)esi + 0x14)) & 0x0000FFFF;

	if(eax < 0xE0)
		return 0;

	eax = ntheader->OptionalHeader.Magic & 0x0000FFFF; // +18

	if(ntheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		IMAGE_NT_HEADERS32 *ntHeader32 = ntheader;
		if(ntHeader32->OptionalHeader.NumberOfRvaAndSizes <= 0x0D)
			return 0;

		PESectionAlignment = ntHeader32->OptionalHeader.SectionAlignment;
		PEImageBase = (void*) ntHeader32->OptionalHeader.ImageBase;
		PEImageBaseUpper = 0;
		DataDirectory_Imports = (char*)ntHeader32 + 0x80;
		DataDirectory_Reloc   = (char*)ntHeader32 + 0xA0;
		dir1 = (IMAGE_DATA_DIRECTORY*)((int)ntHeader32 + 0x80);
		dir2 = (IMAGE_DATA_DIRECTORY*)((int)ntHeader32 + 0xA0);
		is32bit = 1;
	}
	else if(ntheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		IMAGE_NT_HEADERS64 *ntHeader64 = (IMAGE_NT_HEADERS64*) ntheader;
		/* 64-bit files, Untested. Probably works. */

		if(ntHeader64->OptionalHeader.NumberOfRvaAndSizes <= 0x0D)
			return 0;

		PESectionAlignment  = ntHeader64->OptionalHeader.SectionAlignment;
		PEImageBase         = (void*) (ntHeader64->OptionalHeader.ImageBase & 0x00000000FFFFFFFFL);
		PEImageBaseUpper    = (void*) (ntHeader64->OptionalHeader.ImageBase >> 32);

		DataDirectory_Imports = (char*)ntHeader64 + 0x90;
		DataDirectory_Reloc   = (char*)ntHeader64 + 0xB0;
		dir1 = (IMAGE_DATA_DIRECTORY*)((int)ntHeader64 + 0x80);
		dir2 = (IMAGE_DATA_DIRECTORY*)((int)ntHeader64 + 0xB0);
		is32bit = 0;
	}
	else
	{
		return 0;
	}

	edx = dir1->VirtualAddress;
	ecx = ntheader->OptionalHeader.SizeOfHeaders;

	DataDirectory_Imports = (char*)ntheader->FileHeader.SizeOfOptionalHeader + ((int)ntheader + 0x18);
	ecx = (ecx + ntheader->OptionalHeader.FileAlignment - 1) & ~(ntheader->OptionalHeader.FileAlignment - 1);

	ld_sha1_update(ctx, baseaddr, ecx);

	if(dir2->VirtualAddress)
		process_reloc(lockdown_heap, baseaddr, is32bit, dir2);
	process_import(lockdown_heap, baseaddr, (void*)dir1->VirtualAddress, dir1->Size, is32bit, dir1->VirtualAddress + baseaddr);
	ldheap_sort(lockdown_heap);

	for(i = 0; i < *((short*)((int)esi + 6)); i++)
		hash1(ctx, lockdown_heap, baseaddr, PEImageBase, (int)PEImageBaseUpper, (int*)(DataDirectory_Imports + (i * 0x28)), PESectionAlignment, lockdown);

	ldheap_destroy(lockdown_heap);

	return 1;

}

int process_reloc(t_lockdown_heap *lockdown_heap, char *baseaddr, BOOL is32bit, IMAGE_DATA_DIRECTORY *reloc)
{
	int eax, edx;
	short *edi;
	char *RelocSectionStart;
	char *RelocSectionEnd;
	int var_8;
	int DataArray[4];

	/* If there's no reloc section, we shouldn't even be here */
	if(reloc->Size == 0)
		return 1;

	RelocSectionStart = reloc->VirtualAddress + baseaddr;
	RelocSectionEnd = reloc->Size + RelocSectionStart;
	if(RelocSectionStart > RelocSectionEnd)
		return 1;

	do
	{
		var_8 = (*((int*)(RelocSectionStart + 4)) - 8) / 2;
		if(var_8 <= 0)
			return 1;

		edi = (short*) (RelocSectionStart + 8);

		do
		{
			eax = *edi / 0x1000;

			if(eax < 0)
				return 0;

			if(eax != 0)
			{
				if(eax == 0x0a)
					edx = 8;
				else if(eax == 3)
					edx = 4;
				else if(eax == 2)
					edx = 2;
				else
					return 0;

				DataArray[0] = *((int*)RelocSectionStart) + (*edi & 0x0FFF);
				DataArray[1] = edx;
				DataArray[2] = 2;
				DataArray[3] = eax;

				ldheap_add(lockdown_heap, (char*)DataArray);
			}

			edi++;
			var_8--;
		} while(var_8);

		RelocSectionStart = (char*) edi;

	} while(RelocSectionStart < RelocSectionEnd);

	return 1;
}

int process_import(t_lockdown_heap *lockdown_heap, void *baseaddr, void *import_sectionoffset, int import_sectionsize, BOOL is32Bit, void *importsection)
{
	int eax, ecx, edx, esi;
	int var_8;
	int DataArray1[4];
	int DataArray2[4];

	eax = (int) importsection;

	if(!importsection || import_sectionsize < 0x14)
		return 1;

	var_8 = 8 - (int)importsection;
	esi = (int)importsection + 0x10;

	do
	{
		if(*((int*) (esi - 4)) == 0)
			return 1;

		edx = *((int*)esi);

		if(edx == 0)
			return 1;

		eax = (int) baseaddr;
		ecx = edx + eax;

		if(is32Bit)
		{
			eax = ecx;
			
			while(*((int*) eax) != 0)
				eax = eax + 4;

			eax = (((eax - ecx) / 4) * 4) + 4;
		}
		else
		{
			/* This block only technically runs on a 64-bit executable, which doesn't exist, 
			 * so it hasn't been tested 100%. I have tested it a little, though. */

			eax = ecx;

			while((*((int*) eax) | *((int*) (eax + 4))) != 0)
				eax = eax + 8;

			eax = (((eax - ecx) / 8) * 8) + 8;
		}

		DataArray1[0] = edx;
		DataArray1[1] = eax;
		DataArray1[2] = 0;
		DataArray1[3] = *((int*)(esi - 0x10));

		ldheap_add(lockdown_heap, (char*) DataArray1);

		DataArray2[0] = (int) import_sectionoffset;
		DataArray2[1] = 0x14;
		DataArray2[2] = 1;
		DataArray2[3] = 0;
		ldheap_add(lockdown_heap, (char*) DataArray2);

		eax = var_8;
		import_sectionoffset = (void*)((int)import_sectionoffset + 0x14);
		esi = esi + 0x14;
		eax = eax + esi - 4;

	} while(eax <= import_sectionsize);

	return 1;
}

/* There are paths in here that are untested for one reason or another. I tried to indicate them as I went along. I am
 * hopeful that they work, but it's always difficult to tell without actually exercising them. 
 * 
 * TODO: The references to the lockdown heap in this should probably be changed to member functions, in the 
 * classic OO-style. */
BOOL hash1(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, char *baseaddr, void *preferred_baseaddr, int preferred_baseaddr_upper, int *section_ptr, int section_alignment, char *lockdown)
{
	int eax, edi;
	int index, dwBytes, var_20;
	int var_30[4], var_40[4];
	int i;
	int *lockdown_memory = (int*) lockdown_heap->memory; /* Lets us address the memory as an int, which cleans up a lot of code. */
	char *allocated_memory_base;

	edi = section_ptr[3];
	var_20 = section_ptr[3];

	dwBytes = ((section_ptr[2] + section_alignment - 1) & ~(section_alignment - 1)) - section_ptr[2];

	if(section_ptr[9] < 0)
	{
		ld_sha1_pad(ctx, dwBytes + section_ptr[2]);
	}
	else
	{
		/* This loop seems to search for the first non-zero block in memory. */
		index = 0;
		if(lockdown_heap->currentlength > 0)
			for(i = 0; index < lockdown_heap->currentlength && lockdown_memory[i] < edi; i += 4)
				index++;

		if(section_ptr[2] > 0)
		{
			char *starting_memory = edi + baseaddr;
			char *ptr_memory = edi + baseaddr;
			int i = 0;
			
			if(section_ptr[2] > 0)
			{
				int memory_offset = index * 4;
				
				do
				{
					int section_length = starting_memory - ptr_memory + section_ptr[2];

					eax = 0;
					if(index < lockdown_heap->currentlength)
						eax = (int)(lockdown_memory[memory_offset] + starting_memory - var_20);

					

					if(eax)
					{
						eax = eax - (int)ptr_memory;

						if(eax < section_length)
							section_length = eax;
					}

					if(section_length)
					{
						ld_sha1_update(ctx, ptr_memory, section_length);
						ptr_memory = ptr_memory + section_length;
					}
					else
					{
						int heap_buffer[0x10];

						memcpy(heap_buffer, lockdown_memory + memory_offset, 0x10);

						hash2(baseaddr, preferred_baseaddr, preferred_baseaddr_upper, ctx, heap_buffer, (void*)ptr_memory, lockdown);

						ptr_memory = ptr_memory + heap_buffer[1];
						index = index + 1;
						memory_offset += 4;
					}
				} while((ptr_memory - starting_memory) < section_ptr[2]);
			}
		}

		if(dwBytes <= 0)
			return 1;

		allocated_memory_base = (char*) HeapAlloc(GetProcessHeap(), 0, dwBytes);

		RtlFillMemory(allocated_memory_base, dwBytes, 0);
		if(dwBytes > 0)
		{
			int i = 0;

			/** This loop only runs once in all my test cases, so I'm not positive that the indexing using "i" will 
			 * work (since that's a large modification of how they did it...) */
			do
			{
				eax = 0;

				if(index < lockdown_heap->currentlength)
				{
					memcpy(var_40, lockdown_heap->memory + (index * 16), 0x10);

					eax = (int)(var_40[0] - section_ptr[2] - var_20 + allocated_memory_base);
				}

				dwBytes = dwBytes + i;

				if(eax)
				{
					eax = eax - ((int*)allocated_memory_base)[i / 4];
					if(eax < dwBytes)
						dwBytes = eax;
				}

				if(dwBytes)
				{
					ld_sha1_update(ctx, &allocated_memory_base[i], dwBytes);
					i = i + dwBytes;
				}
				else
				{
					memcpy(var_30, lockdown_heap->memory + (index * 16), 0x10);

					hash2(baseaddr, (char*)preferred_baseaddr, preferred_baseaddr_upper, ctx, var_30, (int*)(&allocated_memory_base[i]), lockdown);

					index = index + 1;
					i += var_30[4];
				}
			} while(i < dwBytes);
		}

		HeapFree(GetProcessHeap(), 0, (void*) allocated_memory_base);
	}

	return 1;
}

/* Note: not every path gets exercised. What can you do? */
BOOL hash2(char *addr_baseaddr, char *preferred_baseaddr, int preferred_baseaddr_upper, LD_SHA1_CTX *ctx, int *offset_memory, int *ptr_memory, char *lockdown)
{
	int cf = ((addr_baseaddr < preferred_baseaddr) ? 1 : 0);
	int lower_offset = (int)addr_baseaddr - (int)preferred_baseaddr;
	int upper_offset = (addr_baseaddr < 0 ? -1 : 0) - (preferred_baseaddr_upper + cf); /* Used for 64-bit, untested. */
	int buffer[5];
	static int seed1 = -1;
	static int seed2 = -1;
	static char *previous_lockdown = NULL;

	if(!previous_lockdown || strcmp(lockdown, previous_lockdown))
	{
		if(previous_lockdown)
			free(previous_lockdown);
		find_seeds(lockdown, &seed1, &seed2);
		previous_lockdown = strdup(lockdown); /* This is ugly. TODO: Use strdup(). */
	}

	
	if(offset_memory[2] == 0)
	{
		if(offset_memory[3] == 0)
		{
			ld_sha1_pad(ctx, offset_memory[1]);
		}
		else
		{
			ld_sha1_update(ctx, addr_baseaddr + offset_memory[3], offset_memory[1]);
		}
	}
	else if(offset_memory[2] == 1)
	{
		RtlMoveMemory(buffer, (void*) ptr_memory, 0x14);
		buffer[1] = 0;
		buffer[2] = 0;
		ld_sha1_update(ctx, (char*)buffer, 0x14);
	}
	else if(offset_memory[2] == 2)
	{
		if(offset_memory[3] == 1)
		{
			/* 8-bit files? *shrug* I don't know what this does, but it's untested. */
			short value = ((((*((short*)(ptr_memory)) << 0x10) - lower_offset) >> 0x10) ^  (seed1 & 0x0000FFFF)) & 0x0000FFFF;
			ld_sha1_update(ctx, (char*)&value, 2);
		}
		else if(offset_memory[3] == 2)
		{
			/* Likely for 16-bit files, untested. */
			short value = (((*((short*)(ptr_memory)) - lower_offset)) ^ (seed1 & 0x0000FFFF)) & 0x0000FFFF;
			ld_sha1_update(ctx, (char*)&value, 2);
		}
		else if(offset_memory[3] == 3)
		{
			/* Likely for 32-bit files, tested. */
			int value = (ptr_memory[0] - lower_offset) ^ seed1;
			ld_sha1_update(ctx, (char*)&value, 4);
		}
		else if(offset_memory[3] == 10)
		{
			/* Likely for 64-bit files, untested.. actually prety sure that this won't work, we 
			 * likely need to define an array for ecx and lower_offset, and hash them together. Guess that's
			 * a TODO if 64-bit games become common.
			 * Update: It'll probably work now. But who knows? */
			int value[2];

			cf = (ptr_memory[0] < lower_offset ? 1 : 0);
			value[0] = (ptr_memory[0] - lower_offset)        ^ seed1;
			value[1] = (ptr_memory[1] - (upper_offset + cf)) ^ seed2;

			ld_sha1_update(ctx, (char*)value, 8);
		}
	}
	else
	{
		return 0;
	}

	return 1;
}

int string_combine(char *str1, int *length, char *str2)
{
	int i, j;
	unsigned short word1, word2;
	char *ptr_str1 = str1;
	int ret = TRUE;
	
	for(i = 0x10; i > 0; )
	{
		/* Skips over null bytes. */
		while(i && !str2[i - 1])
			i--;

		if(i)
		{
			word1 = 0;

			for(j = i - 1; j >= 0; j--)
			{
				word2 = (word1 << 8) + (str2[j] & 0xFF);
				word_shifter(&word2, &word1);
				str2[j] = (char) word2;
			}

			if((0x10 - i) >= *length)
				ret = FALSE;
			else
				ptr_str1[0] = word1 + 1;

			ptr_str1++;
		}
	}

	*length = ptr_str1 - str1;

	return ret;
}


/* Takes two word values and does a whole bunch of math on them. */
void word_shifter(unsigned short *str1, unsigned short *str2)
{
	*str2 = (((*str1 >> 8) + (*str1 & 0xFF)) >> 8) + ((((*str1 >> 8) + (*str1 & 0xFF)) & 0xFF));
	*str2 = (*str2 & 0xFFFFFF00) | (((*str2 + 1) & 0xFF) - (((*str2 & 0xFF) != 0xFF) ? 1 : 0));

	*str1 = ((*str1 - *str2) & 0xFFFF00FF) | (((((*str1 - *str2) >> 8) & 0xFF) + 1) ? 0 : 0x100);
	*str1 = (*str1 & 0xFFFFFF00) | (-*str1 & 0x000000FF);
}

/* I'm positive there's a better way to do this one, but I really don't care. :) 
 * It occurs to me that this is likely a broken implementation of, 
 *  if(num1<num2) return -1; else return 1; 
 * Since this is passed to a sort function. 
 * Update: I changed my mind: I'm pretty sure that this is just unsigned. D'oh! 
 * I don't actually use this function, so I'll just leave it intact as a symbol
 * of why I should be more caeful. :) */
int number_compare_deprecated(int *num1, int *num2)
{
	if(*num1 == *num2)
		return 0;

	if(*num2 < *num1 && *num1 < 0 && *num2 < 0)
		return 1;
	else if(*num1 < 0 && *num2 == 0)
		return 1;
	else if(*num1 > *num2 && *num2 >= 0)
		return 1;
	else if(*num1 < 0 && *num2 > 0)
		return 1;
	else
		return -1;
}

/* This is an odd way of including a header, see the comment at the top for more information. */
#include "lockdowntests.h"

