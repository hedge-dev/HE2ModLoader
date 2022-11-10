#pragma once

typedef HRESULT(__fastcall CreateDevice)(
    void    *pAdapter,
    void*   DriverType,
    HMODULE Software,
    UINT    Flags,
    void    *pFeatureLevels,
    UINT    FeatureLevels,
    UINT    SDKVersion,
    void    **ppDevice,
    void    *pFeatureLevel,
    void    **ppImmediateContext);

typedef HRESULT(__fastcall CoreCreateDevice)(
    void    *pAdapter,
    void*   DriverType,
    HMODULE Software,
    UINT    Flags,
    void    *pFeatureLevels,
    UINT    FeatureLevels,
    UINT    SDKVersion,
    void    **ppDevice,
    void    *pFeatureLevel,
    void    **ppImmediateContext);

typedef HRESULT(__fastcall CreateDeviceAndSwapChain)(
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
    void    **ppImmediateContext);
void HookDirectX();