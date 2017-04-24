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

#ifndef __MY_LOCKDOWNSHA1_H__
#define __MY_LOCKDOWNSHA1_H__

#include "lockdown_heap.h"
#include "lockdown_sha1.h"

/** This is really the core of everything: CheckRevision(). It performs all
 * the version checks, and is the only interface to this library. */
BOOL CheckRevision(char *valuestring, char *lockdownfile, int *out_hashbuf1, char out_hashbuf2[0x10], char *imagedump, char *file1, char *file2, char *file3);

/* A test function. May not be defined. */
void test_all_lockdown();

#endif;