#ifndef __MEMORY_PATCHES_LOAD_HOOKS_H__
#define __MEMORY_PATCHES_LOAD_HOOKS_H__

#include <windows.h>

void set_module(HMODULE hModule);
void patch_load_library();
void unpatch_load_library();

void __stdcall patchfunc_loadlibrary(char *library);

#endif