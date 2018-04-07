#pragma once

/// <summary>Detours the export entry from the export table in memory on Windows x64/x86</summary>
/// <param name="hModuleBase">address of dll</param>
/// <param name="pExportToHook">name of the export (this is case sensitive)</param>
/// <param name="HookFnc">address of the function to call instead</param>
/// <returns>returns the address of the original export table entry</returns>
void* HookExportTable( HMODULE hModuleBase, char* pExportToHook, void* HookFnc );
