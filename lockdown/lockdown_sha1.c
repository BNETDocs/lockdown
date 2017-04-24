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
#include "lockdown_sha1.h"

void ld_sha1_tweedle(int *ptr_rotator, int bitwise, int bitwise2, int bitwise3, int *ptr_adder, int *ptr_ret)
{
    *ptr_ret = *ptr_ret + (((RotateLeft32(bitwise3, 5)) + ( (~(*ptr_rotator) & bitwise2) | (*ptr_rotator & bitwise))) + *ptr_adder + 0x5A827999);
	*ptr_adder = 0;
	*ptr_rotator = RotateLeft32(*ptr_rotator, 0x1e);
}

void ld_sha1_twitter(int *ptr_rotator, int bitwise, int rotator2, int bitwise2, int *ptr_rotator3, int *ptr_ret)
{
	*ptr_ret = *ptr_ret + ((((bitwise2 | bitwise) & *(ptr_rotator)) | (bitwise2 & bitwise)) + ((RotateLeft32(rotator2, 5)) + *ptr_rotator3) - 0x70e44324);
	*ptr_rotator3 = 0;
	*ptr_rotator = RotateLeft32(*ptr_rotator, 0x1e);
}

void ld_sha1_transform(int *data, int *state)
{
	int a, b, c, d, e, f, g, h, m, n;
	int i;

	int buf[80];

	memcpy(buf, data, 0x40);

	for(i = 0; i < 0x40; i++)
		buf[i + 16] = RotateLeft32(buf[i + 13] ^ buf[i + 8] ^ buf[i + 0] ^ buf[i + 2], 1);

	m = state[0];
	b = state[1];
	c = state[2];
	n = state[3];
	e = state[4];

	for(i = 0; i < 20; i += 5)
	{
		ld_sha1_tweedle(&b, c, n, m, &buf[0 + i], &e);
		ld_sha1_tweedle(&m, b, c, e, &buf[1 + i], &n);
		ld_sha1_tweedle(&e, m, b, n, &buf[2 + i], &c);
		ld_sha1_tweedle(&n, e, m, c, &buf[3 + i], &b);
		ld_sha1_tweedle(&c, n, e, b, &buf[4 + i], &m);
	}

	f = m;
	d = n;

	for(i = 0x14; i < 0x28; i += 5)
	{
		g =  buf[i] + RotateLeft32(f, 5) + (d ^ c ^ b);
		d = d + RotateLeft32(g + e + 0x6ed9eba1, 5) + (c ^ RotateLeft32(b, 0x1e) ^ f) + buf[i + 1] + 0x6ed9eba1;
		c = c + RotateLeft32(d, 5) + ((g + e + 0x6ed9eba1) ^ RotateLeft32(b, 0x1e) ^ RotateLeft32(f, 0x1e)) + buf[i + 2] + 0x6ed9eba1;
		e = RotateLeft32(g + e + 0x6ed9eba1, 0x1e);
		b = RotateLeft32(b, 0x1e) + RotateLeft32(c, 5) + (e ^ d ^ RotateLeft32(f, 0x1e)) + buf[i + 3] + 0x6ed9eba1;
		d = RotateLeft32(d, 0x1e);
		f = RotateLeft32(f, 0x1e) + RotateLeft32(b, 5) + (e ^ d ^ c) + buf[i + 4] + 0x6ed9eba1;
		c = RotateLeft32(c, 0x1e);

		memset(buf, 0, 20);

	} while(i < 0x28);

	m = f;
	n = d;
	
	for(i = 0x28; i < 0x3c; i += 5)
	{
		ld_sha1_twitter(&b, n, m, c, &buf[i + 0], &e);
		ld_sha1_twitter(&m, c, e, b, &buf[i + 1], &n);
		ld_sha1_twitter(&e, b, n, m, &buf[i + 2], &c);
		ld_sha1_twitter(&n, m, c, e, &buf[i + 3], &b);
		ld_sha1_twitter(&c, e, b, n, &buf[i + 4], &m);
	} 

	f = m;
	a = m;
	d = n;

	for(i = 0x3c; i < 0x50; i += 5)
	{
		g = RotateLeft32(a, 5) + (d ^ c ^ b) + buf[i + 0] + e - 0x359d3e2a;
		b = RotateLeft32(b, 0x1e);
		e = g;
		d = (c ^ b ^ a) + buf[i + 1] + d + RotateLeft32(g, 5) - 0x359d3e2a;
		a = RotateLeft32(a, 0x1e);
		g = RotateLeft32(d, 5);
		g = (e ^ b ^ a) + buf[i + 2] + c + g - 0x359d3e2a;
		e = RotateLeft32(e, 0x1e);
		c = g;
		g = RotateLeft32(g, 5) + (e ^ d ^ a) + buf[i + 3] + b - 0x359d3e2a;
		d = RotateLeft32(d, 0x1e);
		h = (e ^ d ^ c) + buf[i + 4];
		b = g;
		g = RotateLeft32(g, 5);
		c = RotateLeft32(c, 0x1e);
		a = (h + a) + g - 0x359d3e2a;

		buf[i + 0] = 0;
		buf[i + 1] = 0;
		buf[i + 2] = 0;
		buf[i + 3] = 0;
		buf[i + 4] = 0;
	} while(i < 0x50);

	state[0] = state[0] + a;
	state[1] = state[1] + b;
	state[2] = state[2] + c;
	state[3] = state[3] + d;
	state[4] = state[4] + e;
}

void ld_sha1_init(LD_SHA1_CTX *ctx)
{
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;
	ctx->state[0]  = 0x67452301;
	ctx->state[1]  = 0xEFCDAB89;
	ctx->state[2]  = 0x98BADCFE;
	ctx->state[3]  = 0x10325476;
	ctx->state[4]  = 0xC3D2E1F0;
}

void ld_sha1_update(LD_SHA1_CTX *ctx, char *data, int len)
{
	int *bitlen = ctx->bitlen;
	char *state = (char *) ctx->state;
	int a;
	int b;
	int c;
	int i;

	/* The next two lines multiply len by 8. */
	c = len >> 29;
	b = len << 3;

	a = (bitlen[0] / 8) & 0x3F;

	/* Check for overflow. */
	if(bitlen[0] + b < bitlen[0] || bitlen[0] + b < b)
		bitlen[1]++;
	bitlen[0] = bitlen[0] + b;
	bitlen[1] = bitlen[1] + c;

	len = len + a;
	data = data - a;

	if(len >= 0x40)
	{
		if(a)
		{
			while(a < 0x40)
			{
				state[0x14 + a] = data[a];
				a++;
			}

			ld_sha1_transform((int *) (state + 0x14), (int *) state);
			len -= 0x40;
			data += 0x40;
			a = 0;
		}

		if(len >= 0x40)
		{
			b = len;
			for(i = 0; i < b / 0x40; i++)
			{
				ld_sha1_transform((int *) data, (int *) state);
				len -= 0x40;
				data += 0x40;
			}
		}
	}
	
	for(; a < len; a++)
		state[a + 0x1c - 8] = data[a];

	return;
}

void ld_sha1_final(LD_SHA1_CTX *ctx, int *hash)
{
	int i;
	int vars[2];
	char *MysteryBuffer = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

	vars[0] = ctx->bitlen[0];
	vars[1] = ctx->bitlen[1];

	ld_sha1_update(ctx, MysteryBuffer, (-((ctx->bitlen[0] >> 3 | ctx->bitlen[1] << 29) + 9) & 0x3f) + 1);
	ld_sha1_update(ctx, (char *)vars, 8);

	for(i = 0; i < 5; i++)
		hash[i] = ctx->state[i];
}

void ld_sha1_pad(LD_SHA1_CTX *ctx, int amount)
{
	char *emptybuffer = malloc(0x1000);
	memset(emptybuffer, 0, 0x1000);

	while(amount > 0x1000)
	{
		ld_sha1_update(ctx, emptybuffer, 0x1000);
		amount -= 0x1000;
	}

	ld_sha1_update(ctx, emptybuffer, amount);
}

BOOL ld_sha1_hash_file(LD_SHA1_CTX *ctx, char *filename)
{
	struct stat filestat;
	FILE *f;
	unsigned char *data;
	size_t actual;

	if(stat(filename, &filestat) < 0 )
	{
		fprintf(stderr, "Error: couldn't stat file %s\n", filename);
		return FALSE;
	}

	fopen_s(&f, filename, "rb");

	if(!f)
	{
		fprintf(stderr, "Error: couldn't open file %s\n", filename);
		return FALSE;
	}

	data = malloc(filestat.st_size);
	actual = fread(data, 1, filestat.st_size, f);

	ld_sha1_update(ctx, data, actual);

	free(data);
	fclose(f);
	
	return TRUE;
}