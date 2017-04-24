#include "MemoryPatch.h"

#include <windows.h>
#include <WindowsX.h>
#include <tchar.h>
#include <malloc.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string.h>


#include "MemoryPatches_LoadHooks.h"

static t_memorypatch *load_library = NULL;
static t_memorypatch *lockdown = NULL;

static BOOL display_system_calls = TRUE;

void patch_load_library()
{
	HMODULE addrKernel32 = GetModuleHandle("kernel32");
	FARPROC addrLoadLibraryA = GetProcAddress(addrKernel32, "LoadLibraryA");
	
	if(!load_library)
	{
		load_library = mp_initialize_useful(addrLoadLibraryA, (void*) patchfunc_loadlibrary, 5);
		mp_add_memoryoffset_parameter(load_library, EBP, 8);
	}
	mp_apply(load_library);
}

void unpatch_load_library()
{
	if(load_library)
		mp_remove(load_library);
	load_library = NULL;
}

void __stdcall patchfunc_lockdown(char *data)
{
	static FILE *f = NULL;

	if(!f)
		fopen_s(&f, "screendump.bin", "wb");
	fwrite(data, 0xd0, 1, f);
}

void __stdcall patchfunc_loadlibrary(char *library)
{
	if(strstr(library, "IX86") && strstr(library, "lockdown"))
	{
		HMODULE hLockdown = LoadLibraryEx("lockdown-IX86-00.dll", NULL, 0);
		strcpy_s(library, strlen(library) + 1, "lockdown-IX86-00.dll");

		lockdown = mp_initialize((void*)((int)hLockdown + 0x1B53), patchfunc_lockdown, 15);
		mp_add_register_parameter(lockdown, EDI);
		mp_set_preserve_registers(lockdown, TRUE);

		mp_apply(lockdown);
	}
}


