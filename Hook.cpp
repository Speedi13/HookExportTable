#include "Hook.h"

/// <summary>Detours the export entry from the export table in memory on Windows x64/x86</summary>
/// <param name="hModuleBase">address of dll</param>
/// <param name="pExportToHook">name of the export (this is case sensitive)</param>
/// <returns>returns the address of the original export table entry</returns>
void* HookExportTable( HMODULE hModuleBase, char* pExportToHook, void* HookFnc )
{
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModuleBase;
	if ( !pDosHeader )
		return NULL;

	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return NULL;
#ifdef _AMD64_
	IMAGE_NT_HEADERS64* pNtHeader = (IMAGE_NT_HEADERS64*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#else
	IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)( (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew );
#endif
	if ( pNtHeader->Signature != IMAGE_NT_SIGNATURE )
		return NULL;

#ifdef _AMD64_
	//Check if dll is x64
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return NULL;
#else
	//Check if dll is x86
	if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return NULL;
#endif

#ifdef _AMD64_
	DWORD_PTR dwFncModuleDelta = NULL;
	
	dwFncModuleDelta = max( (DWORD_PTR)(hModuleBase), (DWORD_PTR)(HookFnc) ) - min( (DWORD_PTR)(hModuleBase), (DWORD_PTR)(HookFnc) );

	if ( dwFncModuleDelta > (DWORD32)( MAXDWORD32 ) )
		return NULL; //sadly not possible... you might should take a loot at the import table
#endif

	IMAGE_DATA_DIRECTORY* pExportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	DWORD ExportEntryRVA = pExportDir->VirtualAddress;
	if ( !ExportEntryRVA ) //check if export table present
		return NULL;

	DWORD ExportEntrySize = pExportDir->Size;
	if ( !ExportEntrySize )
		return NULL;

	IMAGE_EXPORT_DIRECTORY* pExportTable = (IMAGE_EXPORT_DIRECTORY*)( (DWORD_PTR)pDosHeader + ExportEntryRVA );

	//check if any export names are present
	if ( !pExportTable->AddressOfNames )
		return NULL;

	DWORD* ExportNames = (DWORD*)( (DWORD_PTR)pDosHeader + pExportTable->AddressOfNames );
	DWORD* Functions = (DWORD*)( (DWORD_PTR)pDosHeader + pExportTable->AddressOfFunctions );
	WORD* Ordinals = (WORD*)( (DWORD_PTR)pDosHeader + pExportTable->AddressOfNameOrdinals );
	
	for (DWORD i = 0; i < pExportTable->NumberOfFunctions; i++)
	{
		char* pExportName = (char*)( (DWORD_PTR)pDosHeader + ExportNames[i] );
		WORD OrdIndex = (WORD)Ordinals[i];

		DWORD_PTR ExportFncOffset = Functions[OrdIndex];
		if ( !ExportFncOffset )
			continue;

		if ( strcmp( pExportName, pExportToHook) != NULL ) //or use stricmp to prevent Case Sensitivity problems
			continue;
		
		DWORD_PTR ExportFnc = (DWORD_PTR)pDosHeader + ExportFncOffset;

		//todo: support forwarded exports:
		if (ExportFnc > ((DWORD_PTR)pExportTable) && 
			ExportFnc < ((DWORD_PTR)pExportTable + ExportEntrySize))
		{
			char* pForwardedString = (char*)ExportFnc;
			//printf("[Export] %s ==> %s\n",pExportName,pForwardedString);
			return NULL;
		}

		DWORD_PTR QWord_Offset = (DWORD_PTR)HookFnc - (DWORD_PTR)hModuleBase;
#ifdef _AMD64_
		QWord_Offset &= 0xFFFFFFFF;
#endif
		DWORD dwOffset = QWord_Offset;

		DWORD* pRelativeOffset = &Functions[OrdIndex];

		DWORD dwOldProtection = NULL;
		VirtualProtect( (void*)pRelativeOffset, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection );

		*(DWORD*)pRelativeOffset = dwOffset;

		VirtualProtect( (void*)pRelativeOffset, sizeof(DWORD), dwOldProtection, NULL );

		if ( *(DWORD*)pRelativeOffset != ExportFncOffset )
			return (void*)ExportFnc;
		else
			return NULL;
	}
	return NULL;
}
