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

#ifndef __LOCKDOWN_SHA1_H__
#define __LOCKDOWN_SHA1_H__

/* Standard SHA1 stuff. */
typedef struct
{
	int bitlen[2];
	int state[32];
} LD_SHA1_CTX;


void ld_sha1_tweedle(int *ptr_rotator, int bitwise, int bitwise2, int bitwise3, int *ptr_adder, int *ptr_ret);
void ld_sha1_twitter(int *ptr_rotator, int bitwise, int rotator2, int bitwise2, int *ptr_rotator3, int *ptr_ret);
void ld_sha1_transform(int *data, int *state);

void ld_sha1_init(LD_SHA1_CTX *ctx);
void ld_sha1_update(LD_SHA1_CTX *ctx, char *data, int len);
void ld_sha1_final(LD_SHA1_CTX *ctx, int *hash);

void ld_sha1_pad(LD_SHA1_CTX *sha1, int amount);
BOOL ld_sha1_hash_file(LD_SHA1_CTX *ctx, char *filename);

#endif