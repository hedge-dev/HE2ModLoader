#include "pch.h"
#include "Direct3DHook.h"
#include "windows.h"
#include "stdio.h"
#include <Unknwn.h>
#include "detours.h"

#pragma warning(disable:6387)

HMODULE hD3D;
#define MAKE_STUB(NAME) void __declspec(dllexport) NAME() { MessageBoxA(NULL, "Attempted to call unloaded function: " #NAME, "HE2ML", 0); *(int*)0 = 0; }

extern "C"
{
    // d3d11.dll
    MAKE_STUB(CreateDirect3D11DeviceFromDXGIDevice);
    MAKE_STUB(CreateDirect3D11SurfaceFromDXGISurface);
    MAKE_STUB(D3D11CoreCreateDevice);
    MAKE_STUB(D3D11CoreCreateLayeredDevice);
    MAKE_STUB(D3D11CoreGetLayeredDeviceSize);
    MAKE_STUB(D3D11CoreRegisterLayers);
    MAKE_STUB(D3D11CreateDevice);
    MAKE_STUB(D3D11CreateDeviceAndSwapChain);
    MAKE_STUB(D3D11CreateDeviceForD3D12);
    MAKE_STUB(D3D11On12CreateDevice);
    MAKE_STUB(D3DKMTCloseAdapter);
    MAKE_STUB(D3DKMTCreateAllocation);
    MAKE_STUB(D3DKMTCreateContext);
    MAKE_STUB(D3DKMTCreateDevice);
    MAKE_STUB(D3DKMTCreateSynchronizationObject);
    MAKE_STUB(D3DKMTDestroyAllocation);
    MAKE_STUB(D3DKMTDestroyContext);
    MAKE_STUB(D3DKMTDestroyDevice);
    MAKE_STUB(D3DKMTDestroySynchronizationObject);
    MAKE_STUB(D3DKMTEscape);
    MAKE_STUB(D3DKMTGetContextSchedulingPriority);
    MAKE_STUB(D3DKMTGetDeviceState);
    MAKE_STUB(D3DKMTGetDisplayModeList);
    MAKE_STUB(D3DKMTGetMultisampleMethodList);
    MAKE_STUB(D3DKMTGetRuntimeData);
    MAKE_STUB(D3DKMTGetSharedPrimaryHandle);
    MAKE_STUB(D3DKMTLock);
    MAKE_STUB(D3DKMTOpenAdapterFromHdc);
    MAKE_STUB(D3DKMTOpenResource);
    MAKE_STUB(D3DKMTPresent);
    MAKE_STUB(D3DKMTQueryAdapterInfo);
    MAKE_STUB(D3DKMTQueryAllocationResidency);
    MAKE_STUB(D3DKMTQueryResourceInfo);
    MAKE_STUB(D3DKMTRender);
    MAKE_STUB(D3DKMTSetAllocationPriority);
    MAKE_STUB(D3DKMTSetContextSchedulingPriority);
    MAKE_STUB(D3DKMTSetDisplayMode);
    MAKE_STUB(D3DKMTSetDisplayPrivateDriverFormat);
    MAKE_STUB(D3DKMTSetGammaRamp);
    MAKE_STUB(D3DKMTSetVidPnSourceOwner);
    MAKE_STUB(D3DKMTSignalSynchronizationObject);
    MAKE_STUB(D3DKMTUnlock);
    MAKE_STUB(D3DKMTWaitForSynchronizationObject);
    MAKE_STUB(D3DKMTWaitForVerticalBlankEvent);
    MAKE_STUB(D3DPerformance_BeginEvent);
    MAKE_STUB(D3DPerformance_EndEvent);
    MAKE_STUB(D3DPerformance_GetStatus);
    MAKE_STUB(D3DPerformance_SetMarker);
    MAKE_STUB(EnableFeatureLevelUpgrade);
    MAKE_STUB(OpenAdapter10);
    MAKE_STUB(OpenAdapter10_2);
}


void ResolveStubMethods(void* self, void* module)
{
#define MAP(MODULE, ADDRESS) ((char*)(MODULE) + (unsigned)(ADDRESS))

    HMODULE executingModule = (HMODULE)self;

    const auto* header = reinterpret_cast<IMAGE_DOS_HEADER*>(executingModule);
    const auto* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(MAP(executingModule, header->e_lfanew));

    const auto* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(MAP(executingModule, ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));

    const DWORD* names = reinterpret_cast<DWORD*>(MAP(executingModule, exportDir->AddressOfNames));
    for (size_t i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* name = MAP(executingModule, names[i]);
        void* newProc = reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(module), name));

        if (newProc)
        {
            const DWORD* functions = reinterpret_cast<DWORD*>(MAP(executingModule, exportDir->AddressOfFunctions));
            const WORD* ordinals = reinterpret_cast<WORD*>(MAP(executingModule, exportDir->AddressOfNameOrdinals));

            const DWORD function = functions[ordinals[i]];
            void* oldProc = MAP(executingModule, function);

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&oldProc, newProc);
            DetourTransactionCommit();
        }
    }
}

#undef MAP

void HookDirectX(void* self)
{
    char windir[MAX_PATH];
    GetSystemDirectoryA(windir, MAX_PATH);
    char d3d[MAX_PATH];
    snprintf(d3d, MAX_PATH, "%s\\d3d11.dll", windir);
    hD3D = LoadLibraryA(d3d);
    ResolveStubMethods(self, hD3D);
}