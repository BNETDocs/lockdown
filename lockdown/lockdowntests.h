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

/** lockdowntests.h
 * This isn't really a header file, it's a list of function implementations. I wanted to 
 * keep them separate, and to be able to stop them from being compiled whenever I wanted, 
 * so I put them in here. It's included in exactly one place (at the bottom of MyLockdown.c), 
 * if it's included anywhere else a linker error will occur. 
 *
 * test_all_lockdown() should be run every time changes are made, it should exercise almost every path 
 * in the lockdown code. 
 */

#if 1

HMODULE ix86;

BOOL test_tweedle()
{
	int rotator, real_rotator;
	int bitwise;
	int bitwise2;
	int bitwise3;
	int adder, real_adder;
	int ret, real_ret;
	int i;


	for(i = 0; i < 5000; i++)
	{
		rotator = real_rotator = rand();
		bitwise = rand();
		bitwise2 = rand();
		bitwise3 = rand();
		adder = real_adder = rand();
		ret = real_ret = rand();

		real_sha1_tweedle(&real_rotator, bitwise, bitwise2, bitwise3, &real_adder, &real_ret);
		ld_sha1_tweedle(&rotator, bitwise, bitwise2, bitwise3, &adder, &ret);

		if(rotator != real_rotator || adder != real_adder || ret != real_ret)
			return FALSE;
	}
	return TRUE;
}

BOOL test_twitter()
{
	int rotator, real_rotator;
	int bitwise;
	int rotator2;
	int bitwise2;
	int rotator3, real_rotator3;
	int ret, real_ret;
	int i;

	for(i = 0; i < 5000; i++)
	{
		rotator = real_rotator = rand();
		bitwise = rand();
		rotator2 = rand();
		bitwise2 = rand();
		rotator3 = real_rotator3 = rand();
		ret = real_ret = rand();

		real_sha1_tweedle(&real_rotator, bitwise, rotator2, bitwise2, &real_rotator3, &real_ret);
		ld_sha1_tweedle(&rotator, bitwise, rotator2, bitwise2, &rotator3, &ret);

		if(rotator != real_rotator || rotator3 != real_rotator3 || ret != real_ret)
			return FALSE;
	}
	return TRUE;
}

BOOL test_transform()
{
	int data[64];
	int state[5];
	int real_state[5];
	int i, j;

	for(i = 0; i < 5; i++)
		state[i] = real_state[i] = rand();

	for(i = 0; i < 500; i++)
	{
		for(j = 0; j < 64; j++)
			data[j] = rand();

		real_sha1_transform(data, real_state);
		ld_sha1_transform(data, state);



		if(memcmp(state, real_state, 4))
			return FALSE;
	}

	return TRUE;
}

BOOL test_sha1()
{
	LD_SHA1_CTX ctx;
	real_LD_SHA1_CTX real_ctx;

	char *data = "1234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456";
	int i;
	int len = 0;
	char buf[64];
	char real_buf[64];

	ld_sha1_init(&ctx);
	real_sha1_init(&real_ctx);
	if(memcmp(&ctx, &real_ctx, sizeof(LD_SHA1_CTX)))
		return FALSE;

	for(i = 0; i < 5000; i++)
	{
		int len = (i + 10) % 1023;

		real_sha1_update(&real_ctx, data, len);
		ld_sha1_update(&ctx, data, len);
		if(memcmp(&ctx, &real_ctx, sizeof(LD_SHA1_CTX)))
			return FALSE;

		ld_sha1_final(&ctx, (int *)buf);
		real_sha1_final(&real_ctx, real_buf);
		if(memcmp(buf, real_buf, 64))
			return FALSE;

	}

	return TRUE;
}

BOOL test_valuestring()
{
//	char str[] = "\xC3\xCE\xC1\x35\xCC\x50\xE7\xCC\x02\xAB\x6C\xDA\xAC\x71\xDE\xB6";
	char str[] = "\x07\x34\x4B\x13\x3F\x65\x1C\x87\x26\x93\x31\x0E\x8F\xCF\x34\x0D\x02";
	char real_buffer[16];
	char buffer[16];
	int i, j;
	BOOL real_goodstr;
	BOOL goodstr;

	for(i = 0; i < 10000; i++)
	{
//		printf("%d\n", i);
		for(j = 0; j < 16; j++)
			str[j] = (rand() & 0x000000FF);

		for(j = 0; j < 10; j++)
		{
			str[16] = j;

			real_goodstr = real_shuffle_value_string(str, strlen(str), real_buffer);
			goodstr = shuffle_value_string(str, strlen(str), buffer);

			if(real_goodstr && !goodstr)
			{
				printf("Rejected a string that the real one accepted\n");
				return FALSE;
			}
			else if(!real_goodstr && goodstr)
			{
				printf("Accepted a string that the real one rejected\n");
				return FALSE;
			}
			else if(real_goodstr && goodstr)
			{
				if(memcmp(buffer, real_buffer, 16))
					return FALSE;
			}
		}
	}

	return TRUE;
}

BOOL test_stringshifter()
{
	unsigned short word1;
	unsigned short word2;

	unsigned short real_word1;
	unsigned short real_word2;

	int i;

	for(i = 0; i < 1000000; i++)
	{
		word1 = real_word1 = rand();
		word2 = real_word2 = rand();

//		printf("%04x %04x\n", word1, word2);
		real_word_shifter(&real_word1, &real_word2);
		word_shifter(&word1, &word2);

//		printf("%04x %04x\n", real_word1, real_word2);
//		printf("%04x %04x\n\n", word1, word2);

		if(word1 != real_word1)
			return FALSE;
		if(word2 != real_word2)
			return FALSE;
	}

	return TRUE;
}

BOOL test_string_combine()
{
	char buf1[] = "0123456789abcdef";
	char buf2[] = "fedcba9876543210";
	int length = 16;
	int ret;
	char real_buf1[] = "0123456789abcdef";
	char real_buf2[] = "fedcba9876543210";
	int real_length = 16;
	int real_ret;
	int i, j;

	for(i = 0; i < 10000; i++)
	{
		length = real_length = 16;
		for(j = 0; j < 16; j++)
		{
			buf1[j] = real_buf1[j] = (rand() % 0xFE) + 1;
			buf2[j] = real_buf2[j] = (rand() % 0xFE) + 1;
		}

		real_ret = real_string_combine(real_buf1, &real_length, real_buf2);
		ret = string_combine(buf1, &length, buf2);

//		printf("[REAL] Ret: %08x  Length: %d\n", real_ret, real_length);
//		print_hash(real_buf1, 16);
//		print_hash(real_buf2, 16);
//		printf("\n");

//		printf("[MINE] Ret: %08x  Length: %d\n", ret, length);
//		print_hash(buf1, 16);
//		print_hash(buf2, 16);

		if(memcmp(buf1, real_buf1, 16))
			return FALSE;
		if(memcmp(buf2, real_buf2, 16))
			return FALSE;
	}
	
	return TRUE;
}

BOOL test_number_compare_deprecated()
{
	int num1;
	int num2;
	int real_num1;
	int real_num2;

	int ret;
	int real_ret;

	int i;

	for(i = 1; i < 500000; i++)
	{
		num1 = real_num1 = ((rand() % i) - (i/2));
		num2 = real_num2 = ((rand() % i) - (i/2));

//		printf("%5d %5d = %d\n", num1, num2, real_number_compare_deprecated(&real_num1, &real_num2));
		real_ret = real_number_compare_deprecated(&real_num1, &real_num2);
		ret = number_compare_deprecated(&num1, &num2);

		if(real_ret != ret)
			return FALSE;
	}

	return TRUE;
}

BOOL test_addtoheap()
{
	t_lockdown_heap *heap1 = ldheap_create();
	t_lockdown_heap *heap2 = ldheap_create();

	char data[] = "ABCDEFGHIJKLMNO";
	int i, j;

	for(i = 0; i < 0x10041; i += 0x40)
	{
		for(j = 0; j < 16; j++)
			data[j] = rand();

		real_AddTolockdown_heap(data, heap1);
		ldheap_add(heap2, data);
		if(!ldheap_compare(heap1, heap2))
			return FALSE;
	}

	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	return TRUE;
}

BOOL test_processreloc()
{
	t_lockdown_heap *heap1 = ldheap_create();
	t_lockdown_heap *heap2 = ldheap_create();

	int stormbase = 0x15000000;
	int battlebase = 0x19000000;
	int storm_reloc_offset = 0x1a0;
	int battle_reloc_offset = 0x1a8;

	real_process_reloc(heap1, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	process_reloc(heap2, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
//	Printlockdown_heap(heap2);
	if(!ldheap_compare(heap1, heap2))
		return FALSE;
	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	real_process_reloc(heap1, (void*) battlebase, FALSE, (void*)(battlebase + battle_reloc_offset));
	process_reloc(heap2, (void*) battlebase, FALSE, (void*)(battlebase + battle_reloc_offset));
//	Printlockdown_heap(heap2);
	if(!ldheap_compare(heap1, heap2))
		return FALSE;
	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	return TRUE;
}

BOOL test_processimport()
{
	t_lockdown_heap *heap1 = ldheap_create();
	t_lockdown_heap *heap2 = ldheap_create();
	int starcraftbase = (int) LoadLibrary("C:\\Program Files\\Starcraft\\Starcraft.exe");
	int stormbase = 0x15000000;
	int battlebase = 0x19000000;

	int starcraft_import_offset = 0x109e24;
	int storm_import_offset = 0x56a74;
	int battle_import_offset = 0x3f4b8;
	int storm_reloc_offset = 0x1a0;
	int battle_reloc_offset = 0x1a8;

	int starcraft_import_size = 0xb4;
	int storm_import_size = 0x8c;
	int battle_import_size = 0xa0;

//	printf("SC: %p\n", starcraftbase);

	real_process_import(heap1, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);
	process_import(heap2, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);
	if(!ldheap_compare(heap1, heap2))
		return FALSE;

	real_process_import(heap1, battlebase, battle_import_offset, battle_import_size, TRUE, battle_import_offset + battlebase);
	process_import(heap2, battlebase, battle_import_offset, battle_import_size, TRUE, battle_import_offset + battlebase);
	if(!ldheap_compare(heap1, heap2))
		return FALSE;

	real_process_import(heap1, starcraftbase, starcraft_import_offset, starcraft_import_size, TRUE, starcraft_import_offset + starcraftbase);
	process_import(heap2, starcraftbase, starcraft_import_offset, starcraft_import_size, TRUE, starcraft_import_offset + starcraftbase);
	if(!ldheap_compare(heap1, heap2))
		return FALSE;

	FreeLibrary((HMODULE) starcraftbase);
	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	return TRUE;
}

BOOL test_arrangerecords()
{
	t_lockdown_heap *heap1 = ldheap_create();
	t_lockdown_heap *heap2 = ldheap_create();
	int starcraftbase = (int) LoadLibrary("C:\\Program Files\\Starcraft\\Starcraft.exe");
	int stormbase = 0x15000000;
	int battlebase = 0x19000000;

	int starcraft_import_offset = 0x109e24;
	int storm_import_offset = 0x56a74;
	int battle_import_offset = 0x3f4b8;

	int storm_reloc_offset = 0x1a0;
	int battle_reloc_offset = 0x1a8;

	int starcraft_import_size = 0xb4;
	int storm_import_size = 0x8c;
	int battle_import_size = 0xa0;

	/* We have to populate the heaps first. */
	real_process_reloc(heap1, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	real_process_import(heap1, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);

	process_reloc(heap2, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	process_import(heap2, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);

	/* Now do the testing. */
	real_ArrangeRecords(heap1->memory, heap1->memory + (heap1->currentlength * 0x10) - 0x10);
	ldheap_sort(heap2);

	if(!ldheap_compare(heap1, heap2))
		return FALSE;

	FreeLibrary((HMODULE) starcraftbase);
	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	return TRUE;
}

BOOL test_ldheap_sort()
{
	t_lockdown_heap *heap1 = ldheap_create();
	t_lockdown_heap *heap2 = ldheap_create();
	int starcraftbase = (int) LoadLibrary("C:\\Program Files\\Starcraft\\Starcraft.exe");
	int stormbase = 0x15000000;
	int battlebase = 0x19000000;

	int starcraft_import_offset = 0x109e24;
	int storm_import_offset = 0x56a74;
	int battle_import_offset = 0x3f4b8;

	int storm_reloc_offset = 0x1a0;
	int battle_reloc_offset = 0x1a8;

	int starcraft_import_size = 0xb4;
	int storm_import_size = 0x8c;
	int battle_import_size = 0xa0;

	/* We have to populate the heaps first. */
	real_process_reloc(heap1, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	real_process_import(heap1, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);

	process_reloc(heap2, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	process_import(heap2, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);

	/* Now do the testing. */
	real_ldheap_sort(heap1->memory, heap1->currentlength);
	ldheap_sort(heap2);

//	Printlockdown_heap(heap2);
//	Printlockdown_heap(heap1);

	if(!ldheap_compare(heap1, heap2))
		return FALSE;

	FreeLibrary((HMODULE) starcraftbase);
	ldheap_destroy(heap2);
	ldheap_destroy(heap1);

	return TRUE;
}

BOOL test_ld_sha1_pad()
{
	int buffer1[0x14];
	int buffer2[0x14];

	LD_SHA1_CTX *ctx1;
	LD_SHA1_CTX *ctx2;
	
	int i;

	for(i = 0; i < 10000; i += 0x10)
	{
		ctx1 = malloc(sizeof(LD_SHA1_CTX));
		ctx2 = malloc(sizeof(LD_SHA1_CTX));

		real_sha1_init(ctx1);
		real_ld_sha1_pad(ctx1, i);
		real_sha1_final(ctx1, buffer1);

		ld_sha1_init(ctx2);
		ld_sha1_pad(ctx2, i);
		ld_sha1_final(ctx2, buffer2);

		if(memcmp(buffer1, buffer2, 0x14))
			return FALSE;

		free(ctx2);
		free(ctx1);
	}

	//print_hash(buffer, 0x14);


	return TRUE;
}

BOOL test_hash1()
{
	t_lockdown_heap *heap1, *heap2;
	int starcraftbase = (int) LoadLibrary("C:\\Program Files\\Starcraft\\Starcraft.exe");
	int stormbase = 0x15000000;
	int battlebase = 0x19000000;

	int starcraft_import_offset = 0x109e24;
	int storm_import_offset = 0x56a74;
	int battle_import_offset = 0x3f4b8;

	int storm_reloc_offset = 0x1a0;
	int battle_reloc_offset = 0x1a8;

	int starcraft_import_size = 0xb4;
	int storm_import_size = 0x8c;
	int battle_import_size = 0xa0;

	int buffer1[0x14], buffer2[0x14];
	LD_SHA1_CTX *ctx1, *ctx2;

	ctx1 = malloc(sizeof(LD_SHA1_CTX));
 	heap1 = ldheap_create();
 	real_process_reloc(heap1, (void*) battlebase, FALSE, (void*)(battlebase + battle_reloc_offset));
 	real_process_import(heap1, battlebase, battle_import_offset, battle_import_size, TRUE, battle_import_offset + battlebase);
 	ldheap_sort(heap1);
 	real_sha1_init(ctx1);
 	real_hash1(ctx1, heap1, 0x19000000, 0x19000000, 0x00000000, 0x19000200, 0x00001000);
 	real_hash1(ctx1, heap1, 0x19000000, 0x19000000, 0x00000000, 0x19000250, 0x00001000);
 	real_hash1(ctx1, heap1, 0x19000000, 0x19000000, 0x00000000, 0x19000278, 0x00001000);
 	real_hash1(ctx1, heap1, 0x19000000, 0x19000000, 0x00000000, 0x190002a0, 0x00001000);
 	real_sha1_final(ctx1, buffer1);
 
 	ctx2 = malloc(sizeof(LD_SHA1_CTX));
 	heap2 = ldheap_create();
 	process_reloc(heap2, (void*) battlebase, FALSE, (void*)(battlebase + battle_reloc_offset));
 	process_import(heap2, battlebase, battle_import_offset, battle_import_size, TRUE, battle_import_offset + battlebase);
 	ldheap_sort(heap2);
 	ld_sha1_init(ctx2);
 	hash1(ctx2, heap2, 0x19000000, 0x19000000, 0x00000000, 0x19000200, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, 0x19000000, 0x19000000, 0x00000000, 0x19000250, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, 0x19000000, 0x19000000, 0x00000000, 0x19000278, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, 0x19000000, 0x19000000, 0x00000000, 0x190002a0, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	real_sha1_final(ctx2, buffer2);
 	if(memcmp(buffer1, buffer2, 0x14))
 		return FALSE;
 
 	ctx1 = malloc(sizeof(LD_SHA1_CTX));
 	heap1 = ldheap_create();
 	real_process_import(heap1, starcraftbase, starcraft_import_offset, starcraft_import_size, TRUE, starcraft_import_offset + starcraftbase);
 	ldheap_sort(heap1);
 	real_sha1_init(ctx1);
 	real_hash1(ctx1, heap1, starcraftbase, 0x00400000, 0x00000000, 0x00400210, 0x00001000);
 	real_hash1(ctx1, heap1, starcraftbase, 0x00400000, 0x00000000, 0x00400238, 0x00001000);
 	real_hash1(ctx1, heap1, starcraftbase, 0x00400000, 0x00000000, 0x00400260, 0x00001000);
 	real_hash1(ctx1, heap1, starcraftbase, 0x00400000, 0x00000000, 0x00400288, 0x00001000);
 	real_sha1_final(ctx1, buffer1);
 
 	ctx2 = malloc(sizeof(LD_SHA1_CTX));
 	heap2 = ldheap_create();
 	process_import(heap2, starcraftbase, starcraft_import_offset, starcraft_import_size, TRUE, starcraft_import_offset + starcraftbase);
 	ldheap_sort(heap2);
 	ld_sha1_init(ctx2);
 	hash1(ctx2, heap2, starcraftbase, 0x00400000, 0x00000000, 0x00400210, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, starcraftbase, 0x00400000, 0x00000000, 0x00400238, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, starcraftbase, 0x00400000, 0x00000000, 0x00400260, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	hash1(ctx2, heap2, starcraftbase, 0x00400000, 0x00000000, 0x00400288, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
 	ld_sha1_final(ctx2, buffer2);
 	if(memcmp(buffer1, buffer2, 0x14))
 		return FALSE;
 
	ctx1 = malloc(sizeof(LD_SHA1_CTX));
	heap1 = ldheap_create();
	process_reloc(heap1, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	process_import(heap1, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);
	ldheap_sort(heap1);
	real_sha1_init(ctx1);
	real_hash1(ctx1, heap1, 0x15000000, 0x15000000, 0x00000000, 0x150001f8, 0x00001000);
	real_hash1(ctx1, heap1, 0x15000000, 0x15000000, 0x00000000, 0x15000220, 0x00001000);
	real_hash1(ctx1, heap1, 0x15000000, 0x15000000, 0x00000000, 0x15000248, 0x00001000);
	real_hash1(ctx1, heap1, 0x15000000, 0x15000000, 0x00000000, 0x15000270, 0x00001000);
	real_hash1(ctx1, heap1, 0x15000000, 0x15000000, 0x00000000, 0x15000298, 0x00001000);
	real_sha1_final(ctx1, buffer1);

	ctx2 = malloc(sizeof(LD_SHA1_CTX));
	heap2 = ldheap_create();
	process_reloc(heap2, (void*) stormbase, FALSE, (void*)(stormbase + storm_reloc_offset));
	process_import(heap2, stormbase, storm_import_offset, storm_import_size, TRUE, storm_import_offset + stormbase);
	ldheap_sort(heap2);
	ld_sha1_init(ctx2);
	hash1(ctx2, heap2, 0x15000000, 0x15000000, 0x00000000, 0x150001f8, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
	hash1(ctx2, heap2, 0x15000000, 0x15000000, 0x00000000, 0x15000220, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
	hash1(ctx2, heap2, 0x15000000, 0x15000000, 0x00000000, 0x15000248, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
	hash1(ctx2, heap2, 0x15000000, 0x15000000, 0x00000000, 0x15000270, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
	hash1(ctx2, heap2, 0x15000000, 0x15000000, 0x00000000, 0x15000298, 0x00001000, "c:\\temp\\lockdown-IX86-00.dll");
	ld_sha1_final(ctx2, buffer2);

	if(memcmp(buffer1, buffer2, 0x14))
		return FALSE;

	return TRUE;
}

BOOL test_hash_file()
{
	LD_SHA1_CTX ctx1;
	LD_SHA1_CTX ctx2;
	char buffer1[0x14];
	char buffer2[0x14];
	int starcraftbase = (int) LoadLibrary("C:\\Program Files\\Starcraft\\Starcraft.exe");
	int ix86base[20];
	int systemstuff[5];
	int i;

	for(i = 0; i < 20; i++)
	{
		char filename[48];
		sprintf(filename, "c:\\temp\\lockdown-ix86-%02d.dll", i);
		ix86base[i] = LoadLibrary(filename);
	}

	systemstuff[0] = LoadLibrary("C:\\windows\\system32\\kernel32.dll");
	systemstuff[1] = LoadLibrary("C:\\windows\\system32\\rnr20.dll");
	systemstuff[2] = LoadLibrary("C:\\windows\\system32\\user32.dll");
	systemstuff[3] = LoadLibrary("C:\\windows\\system32\\ws2_32.dll");
	systemstuff[4] = LoadLibrary("C:\\windows\\system32\\crypt32.dll");

	real_sha1_init(&ctx1);
	real_hash_file(&ctx1,(void*) 0x15000000);
	real_sha1_final(&ctx1, buffer1);
	ld_sha1_init(&ctx2);
	hash_file(&ctx2, (void*) 0x15000000, "c:\\temp\\lockdown-IX86-00.dll");
	ld_sha1_final(&ctx2, buffer2);

	if(memcmp(buffer1, buffer2, 0x14))
		return FALSE;

	real_sha1_init(&ctx1);
	real_hash_file(&ctx1,(void*) 0x19000000);
	real_sha1_final(&ctx1, buffer1);
	ld_sha1_init(&ctx2);
	hash_file(&ctx2, (void*) 0x19000000, "c:\\temp\\lockdown-IX86-00.dll");
	ld_sha1_final(&ctx2, buffer2);

	if(memcmp(buffer1, buffer2, 0x14))
		return FALSE;


	real_sha1_init(&ctx1);
	real_hash_file(&ctx1,(void*) starcraftbase);
	real_sha1_final(&ctx1, buffer1);
	ld_sha1_init(&ctx2);
	hash_file(&ctx2, (void*) starcraftbase, "c:\\temp\\lockdown-IX86-00.dll");
	ld_sha1_final(&ctx2, buffer2);
	if(memcmp(buffer1, buffer2, 0x14))
		return FALSE;


	for(i = 0; i < 20; i++)
	{
		real_sha1_init(&ctx1);
		real_hash_file(&ctx1,(void*) ix86base[i]);
		real_sha1_final(&ctx1, buffer1);
		ld_sha1_init(&ctx2);
		hash_file(&ctx2, (void*) ix86base[i], "c:\\temp\\lockdown-IX86-00.dll");
		ld_sha1_final(&ctx2, buffer2);
		if(memcmp(buffer1, buffer2, 0x14))
			return FALSE;
	}

	for(i = 0; i < 5; i++)
	{
		real_sha1_init(&ctx1);
		real_hash_file(&ctx1,(void*) systemstuff[i]);
		real_sha1_final(&ctx1, buffer1);
		ld_sha1_init(&ctx2);
		hash_file(&ctx2, (void*) systemstuff[i], "c:\\temp\\lockdown-IX86-00.dll");
		ld_sha1_final(&ctx2, buffer2);
		if(memcmp(buffer1, buffer2, 0x14))
			return FALSE;
	}

	for(i = 0; i < 20; i++)
		FreeLibrary(ix86base[i]);

	for(i = 0; i < 5; i++)
		FreeLibrary(systemstuff[i]);

	return TRUE;
}

void test_all_lockdown()
{ 
	/* This seed can be changed, but having the same one made it easier to track down problems. */
	srand(31415926);
	real_sha1_initialize();

	printf("Testing Tweedle... %s\n",        test_tweedle()        ? "PASSED" : "FAILED!!");
	printf("Testing Twotter... %s\n",        test_twitter()        ? "PASSED" : "FAILED!!");
	printf("Testing Transform... %s\n",      test_transform()      ? "PASSED" : "FAILED!!");
	printf("Testing ld_sha1... %s\n",           test_sha1()           ? "PASSED" : "FAILED!!");
	printf("Testing ValueString... %s\n",    test_valuestring()    ? "PASSED" : "FAILED!!");
	printf("Testing StringShifter... %s\n",  test_stringshifter()  ? "PASSED" : "FAILED!!");
	printf("Testing string_combine... %s\n",  test_string_combine()  ? "PASSED" : "FAILED!!");
	printf("Testing number_compare_deprecated... %s\n",  test_number_compare_deprecated()  ? "PASSED" : "FAILED!!");
	printf("Testing AddToHeap... %s\n",      test_addtoheap()      ? "PASSED" : "FAILED!!");
	printf("Testing ProcessReloc... %s\n",   test_processreloc()   ? "PASSED" : "FAILED!!");
	printf("Testing ProcessImport... %s\n",  test_processimport()  ? "PASSED" : "FAILED!!");
	printf("Testing ArrangeRecords... %s\n", test_arrangerecords() ? "PASSED" : "FAILED!!");
	printf("Testing ldheap_sort... %s\n",   test_ldheap_sort()   ? "PASSED" : "FAILED!!");
	printf("Testing ld_sha1_pad... %s\n",      test_ld_sha1_pad()      ? "PASSED" : "FAILED!!");
	printf("Testing Hash1... %s\n",          test_hash1()          ? "PASSED" : "FAILED!!");
	printf("Testing hash_file... %s\n",         test_hash_file()         ? "PASSED" : "FAILED!!");

//	__asm
//	{
//		mov eax, 1234567
//		test eax, eax
//top:
//		shr eax, 1
//		jnz top
//	}
//	__asm
//	{
//		mov eax, 0x40000
//		lea eax, ds:8[eax * 4]
//	}
}
#else

void test_all_lockdown()
{
	printf("Skipping tests....\n");
}

#endif