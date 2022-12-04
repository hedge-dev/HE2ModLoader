#include "pch.h"
#include "Direct3DHook.h"
#include "windows.h"
#include "stdio.h"
#include <Unknwn.h>

#pragma warning(disable:6387)

HMODULE hD3D;
void* DirectXFuncs[3];

void SetupD3DModuleHooks(HMODULE mod)
{
	void* method = GetProcAddress(mod, "D3D11CreateDevice");
	if (method)
		DirectXFuncs[0] = method;

	method = GetProcAddress(mod, "D3D11CoreCreateDevice");
	if (method)
		DirectXFuncs[1] = method;

	method = GetProcAddress(mod, "D3D11CreateDeviceAndSwapChain");
	if (method)
		DirectXFuncs[2] = method;

}

void HookDirectX()
{
    char windir[MAX_PATH];
    GetSystemDirectoryA(windir, MAX_PATH);
    char d3d[MAX_PATH];
    snprintf(d3d, MAX_PATH, "%s\\d3d11.dll", windir);
    hD3D = LoadLibraryA(d3d);
    SetupD3DModuleHooks(hD3D);
}

extern "C"
{
	_declspec(dllexport) HRESULT __fastcall D3D11CreateDevice(
      void    *pAdapter,
      void*   DriverType,
      HMODULE Software,
      UINT    Flags,
      void    *pFeatureLevels,
      UINT    FeatureLevels,
      UINT    SDKVersion,
      void    **ppDevice,
      void    *pFeatureLevel,
      void    **ppImmediateContext)
	{
        return ((CreateDevice*)DirectXFuncs[0])(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
	}

	_declspec(dllexport) HRESULT __fastcall D3D11CoreCreateDevice(
      void    *pAdapter,
      void*   DriverType,
      HMODULE Software,
      UINT    Flags,
      void    *pFeatureLevels,
      UINT    FeatureLevels,
      UINT    SDKVersion,
      void    **ppDevice,
      void    *pFeatureLevel,
      void    **ppImmediateContext)
	{
        return ((CoreCreateDevice*)DirectXFuncs[1])(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
    }

	__declspec(dllexport) HRESULT __fastcall D3D11CreateDeviceAndSwapChain(
      void    *pAdapter,
      void*   DriverType,
      HMODULE Software,
      UINT    Flags,
      void    *pFeatureLevels,
      UINT    FeatureLevels,
      UINT    SDKVersion,
      void    *pSwapChainDesc,
      void    **ppSwapChain,
      void    **ppDevice,
      void    *pFeatureLevel,
      void    **ppImmediateContext)
    {
        return ((CreateDeviceAndSwapChain*)DirectXFuncs[2])(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
	}
}