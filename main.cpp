#include <Windows.h>
#include <stdio.h>

HMODULE hookfnc( LPCSTR lpLibFileName )
{
	MessageBoxA(0,lpLibFileName,"HOOK!",0);
	return NULL;
}

int main()
{
	HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );

	//hook:
	//OriFncAddress could be used to call the original function in your hook
	void* OriFncAddress = HookExportTable( hKernel32, "LoadLibraryA" ,&hookfnc );
	printf("OriFncAddress = 0x%p\n", OriFncAddress );
	system("pause");

	

	//Resolve the Import wich should result in our hooking fnc:
	typedef HMODULE (WINAPI* t_LoadLibraryA)( LPCSTR lpLibFileName );
	t_LoadLibraryA FncLoadLibraryA = (t_LoadLibraryA)GetProcAddress( hKernel32, "LoadLibraryA" );
	printf("FncLoadLibraryA = 0x%p\n",FncLoadLibraryA);

	system("pause");

	//Call our hooked import:
	FncLoadLibraryA("nsi.dll");

	system("pause");

	//unhook:
	HookExportTable(GetModuleHandleA( "kernel32.dll" ),"LoadLibraryA",OriFncAddress);
	return 0;
}
