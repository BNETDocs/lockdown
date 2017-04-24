
#include "MemoryPatches_LoadHooks.h"

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		patch_load_library();

		break;

	case DLL_PROCESS_DETACH:
		unpatch_load_library();

		break;
	}
    return TRUE;
}
