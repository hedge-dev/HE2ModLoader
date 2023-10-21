#pragma once

void ResolveStubMethods(void* module);

/// <param name="handle">Modloader handle</param>
void HookSystemDLL(HMODULE handle);