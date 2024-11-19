// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "loader.h"
#include "config.h"
#include <sstream>
#include <CommonLoader.h>
#include <INIReader.h>
#include <detours.h>
#include "helpers.h"
#include "cri.h"
#include "wars.h"
#include "save.h"
#include "Events.h"
#include <d3d11.h>
#include <chrono>
#include "StubFunctions.h"
#include "epic.h"

CMN_LOADER_DEFINE_API_EXPORT
#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)

using std::wstring;

// Base
bool Started = false;
intptr_t BaseAddress = (intptr_t)GetModuleHandle(nullptr);
HANDLE stdoutHandle = nullptr;
ModInfo* ModsInfo;
Game CurrentGame = Game_Unknown;
Platform CurrentPlatform = Platform_Steam;

// File System
vector<char*> ReplaceDirs;
std::map<string, string> FileCache;

// Save File
string* saveFilePath = new string();
bool useSaveFilePath = false;

void PrintError(const char* text, ...)
{
    if (!ConsoleEnabled)
        return;
    va_list ap;
    va_start(ap, text);
    if (!stdoutHandle)
        stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[512];
    _vsprintf_p(buffer, 512, text, ap);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("%s%s\n", "[HE2ML] [ERROR] ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

void PrintWarn(const char* text, ...)
{
    if (!ConsoleEnabled)
        return;
    va_list ap;
    va_start(ap, text);
    if (!stdoutHandle)
        stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[512];
    _vsprintf_p(buffer, 512, text, ap);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
    printf("%s%s\n", "[HE2ML] [WARN]  ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

void PrintDebug(const char* text, ...)
{
    if (!ConsoleEnabled)
        return;
    va_list ap;
    va_start(ap, text);
    if (!stdoutHandle)
        stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[512];
    _vsprintf_p(buffer, 512, text, ap);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("%s%s\n", "[HE2ML] [DEBUG] ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

void PrintInfo(const char* text, ...)
{
    if (!ConsoleEnabled)
        return;
    va_list ap;
    va_start(ap, text);
    if (!stdoutHandle)
        stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[512];
    _vsprintf_p(buffer, 512, text, ap);
    printf("%s%s\n", "[HE2ML] [INFO]  ", buffer);
    va_end(ap);
}

void InitMods();
void InitLoader();
void SetGame(int id);
void SetGameEGS(const char* id);

HOOK(bool, __fastcall, SteamAPI_RestartAppIfNecessary, PROC_ADDRESS("steam_api64.dll", "SteamAPI_RestartAppIfNecessary"), uint32_t appid)
{
    originalSteamAPI_RestartAppIfNecessary(appid);
    std::ofstream ofs("steam_appid.txt");
    ofs << appid;
    ofs.close();

    // Prevent the modloader from restarting
    if (!Started)
    {
        Started = true;
        SetGame(appid);
        InitLoader();
        InitMods();
    }
    return false;
}

HOOK(bool, __fastcall, SteamAPI_IsSteamRunning, PROC_ADDRESS("steam_api64.dll", "SteamAPI_IsSteamRunning"))
{
    originalSteamAPI_IsSteamRunning();
    return true;
}

HOOK(void, __fastcall, SteamAPI_Shutdown, PROC_ADDRESS("steam_api64.dll", "SteamAPI_Shutdown"))
{
    RaiseEvents(modExitEvents);
    originalSteamAPI_Shutdown();
}

HOOK(int64_t, __fastcall, EOS_Initialize, PROC_ADDRESS("EOSSDK-Win64-Shipping.dll", "EOS_Initialize"), EOS_InitializeOptions options)
{
    // Prevent the modloader from restarting
    if (!Started)
    {
        Started = true;
        SetGameEGS(options.productName);
        InitLoader();
        InitMods();
    }

    return originalEOS_Initialize(options);
}

HOOK(int64_t, __fastcall, EOS_Shutdown, PROC_ADDRESS("EOSSDK-Win64-Shipping.dll", "EOS_Shutdown"))
{
    RaiseEvents(modExitEvents);
    return originalEOS_Shutdown();
}

VTABLE_HOOK(HRESULT, WINAPI, IDXGISwapChain, Present, UINT SyncInterval, UINT Flags)
{
    RaiseEvents(modTickEvents);
    CommonLoader::RaiseUpdates();

    return originalIDXGISwapChainPresent(This, SyncInterval, Flags);
}

VTABLE_HOOK(HRESULT, WINAPI, IDXGIFactory, CreateSwapChain, IUnknown* pDevice, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain)
{
    auto result = originalIDXGIFactoryCreateSwapChain(This, pDevice, pDesc, ppSwapChain);

    if (ppSwapChain && *ppSwapChain)
    {
        INSTALL_VTABLE_HOOK(IDXGISwapChain, *ppSwapChain, Present, 8);
    }
    return result;
}

HOOK(HRESULT, WINAPI, _D3D11CreateDevice, PROC_ADDRESS("d3d11.dll", "D3D11CreateDevice"),
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE         DriverType,
    HMODULE                 Software,
    UINT                    Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT                    FeatureLevels,
    UINT                    SDKVersion,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    auto result = original_D3D11CreateDevice(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);

    if (ppDevice && *ppDevice)
    {
        IDXGIDevice1* device{};
        (*ppDevice)->QueryInterface(IID_PPV_ARGS(&device));

        IDXGIAdapter* adapter{};
        if (device)
        {
            device->GetAdapter(&adapter);
        }

        IDXGIFactory* factory{};
        if (adapter)
        {
            adapter->GetParent(IID_PPV_ARGS(&factory));
        }

        if (factory)
        {
            INSTALL_VTABLE_HOOK(IDXGIFactory, factory, CreateSwapChain, 10);
        }

        if (device)
        {
            device->Release();
        }

        if (adapter)
        {
            adapter->Release();
        }

        if (factory)
        {
            factory->Release();
        }
    }

    return result;
}

bool CompareModCount(int id, int count, bool reverse)
{
    if (reverse)
        return id >= 0;
    else
        return id < count;
}
void InDecrease(int* num, bool decrease)
{
    if (decrease)
        (*num)--;
    else
        (*num)++;
}

void SetGame(int id)
{
    if (CurrentPlatform == Platform_Steam)
    {
        CurrentGame = (Game)id;
        PrintDebug("Game ID is %d", CurrentGame);
    }

    switch (CurrentGame)
    {
    case Game_Tenpex:
    case Game_Rangers:
    case Game_Miller:
        RawFolder = "raw";
        break;
    default:
        break;
    }
}

void SetGameEGS(const char* id)
{
    PrintDebug("Product Name is %s", id);

    if (!strcmp(id, "Sonic Frontiers"))
        CurrentGame = Game_Rangers;
    else if (!strcmp(id, "SONIC X SHADOW GENERATIONS"))
        CurrentGame = Game_Miller;
    else
        CurrentGame = Game_Unknown;

    SetGame((int)CurrentGame);
}

bool SupportsSaveRedirection()
{
    // Only Sonic Forces supports save redirection
    return CurrentGame == Game_Wars;
}

bool SupportsSaveRedirectionv2()
{
    // Only Rangers and Miller currently supports this kind of saves
    return CurrentGame == Game_Rangers || CurrentGame == Game_Miller;
}

void InitLoader()
{
    CommonLoader::Init();
    std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();

    InitLoaderCri();

    if (CurrentGame == Game_Wars)
        InitLoaderWars();

    if (SupportsSaveRedirectionv2())
        InitSaveRedirection();
    
    INSTALL_HOOK(_D3D11CreateDevice);

    std::chrono::time_point<std::chrono::steady_clock> end = std::chrono::steady_clock::now();
    std::chrono::milliseconds diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    PrintInfo("Pre-Initialisation completed in %d ms", diff.count());
}

void IndexInclude(string s, size_t rootIndex)
{
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA((s + "\\*").c_str(), &ffd);
    if (INVALID_HANDLE_VALUE == hFind)
        return;
    do
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (ffd.cFileName[0] == '.')
                continue;
            IndexInclude(s + "\\" + ffd.cFileName, rootIndex);
        }
        else
        {
            string key = (s + "\\" + ffd.cFileName).substr(rootIndex);
            string value = s + "\\" + ffd.cFileName;
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            std::replace(value.begin(), value.end(), '/', '\\');
            FileCache[key] = value;
        }
    } while (FindNextFileA(hFind, &ffd) != 0);
}

void InitMods()
{
    ModsInfo = new ModInfo();
    ModsInfo->ModList = new vector<Mod*>();
    ModsInfo->CurrentGame = CurrentGame;
    
    PrintDebug("ModsDB: %s", ModsDbIniPath.c_str());
    INIReader ini(ModsDbIniPath);
    
    char pathbuf[PATH_LIMIT];
    GetModuleFileNameA(NULL, pathbuf, PATH_LIMIT);
    string exePath(pathbuf);
    string exeDir = exePath.substr(0, exePath.find_last_of("\\"));

    vector<ModInitEvent> postEvents;
    vector<string*> strings;

    PrintInfo("Loading Mods...");
    int modCount = ini.GetInteger("Main", "ActiveModCount", 0);
    bool reverse = ini.GetBoolean("Main", "ReverseLoadOrder", false);

    if (reverse)
        PrintInfo("Mods will now be loaded in Reverse!");

    for (int i = (reverse ? (modCount - 1) : 0); CompareModCount(i, modCount, reverse); InDecrease(&i, reverse))
    {
        char key[16];
        snprintf(key, sizeof(key), "ActiveMod%u", i);

        auto modKey = ini.GetString("Main", string(key), "");
        if (modKey.empty())
        {
            PrintError("Invalid mod key detected in ModsDB! \"%s\"", key);
            continue;
        }

        string path = ini.GetString("Mods", modKey, "");
        path = ConvertUnixToWindows(path);
        string dir = GetDirectoryPath(path);

        INIReader modConfig(path);

        auto errorLine = modConfig.ParseError();
        if (errorLine != 0)
        {
            PrintError("Failed to load mod at \"%s\"", path.c_str());
            PrintError("    at %d", errorLine);
        }
        else
        {
            auto mod = new Mod();
            auto modTitle = new string(modConfig.GetString("Desc", "Title", ""));
            auto modPath = new string(path);
            PrintInfo("Loading Mod %d. %s", i, modTitle->c_str());

            mod->Name = modTitle->c_str();
            mod->Path = modPath->c_str();
            strings.push_back(modTitle);
            strings.push_back(modPath);
            ModsInfo->CurrentMod = mod;
            ModsInfo->ModList->push_back(mod);
            
            int dirs = modConfig.GetInteger("Main", "IncludeDirCount", -1);
            if (dirs == -1)
                continue;

            for (int i = 0; i < dirs; i++)
            {
                char key2[14];
                snprintf(key2, sizeof(key2), "IncludeDir%u", i);
                auto path = modConfig.GetString("Main", string(key2), "");
                if (path.empty())
                    break;

                SetCurrentDirectoryA(dir.c_str());
                SetCurrentDirectoryA(path.c_str());
                char* buffer2 = new char[PATH_LIMIT];
                GetCurrentDirectoryA(PATH_LIMIT, buffer2);
                string* replacedir = new string(buffer2);
                if (RawFolder)
                    (*replacedir) += "\\raw\\";
                else if (CurrentGame == Game_Musashi)
                    (*replacedir) += "\\disk\\musashi_0\\";
                else if (CurrentGame == Game_Wars)
                    (*replacedir) += "\\disk\\wars_patch\\";
                else
                    (*replacedir) += "\\data\\";
                PrintDebug("    Added Include: %s", replacedir->c_str());
                ReplaceDirs.push_back((char*)replacedir->c_str());
            }

            // Check save file
            if (SupportsSaveRedirection() || SupportsSaveRedirectionv2())
            {
                auto saveFile = modConfig.GetString("Main", "SaveFile", "");
                if (!saveFile.empty())
                {
                    saveFilePath->clear();
                    saveFilePath->append(dir);
                    saveFilePath->append(saveFile);
                    useSaveFilePath = true;
                    PrintInfo("    Using mod save file for redirection.");
                }
            }

            // Load DLLs
            auto dllFile = modConfig.GetString("Main", "DLLFile", "");
            if (!dllFile.empty())
            {
                SetDllDirectoryA(dir.c_str());
                SetCurrentDirectoryA(dir.c_str());
                std::stringstream stream(dllFile);
                string dllName;
                while (std::getline(stream, dllName, ','))
                {
                    PrintInfo("    Loading DLL: %s", dllName.c_str());
                    HMODULE module = LoadLibraryA((dir + dllName).c_str());
                    if (module)
                    {
                        ModInitEvent init = (ModInitEvent)GetProcAddress(module, "Init");
                        ModInitEvent postInit = (ModInitEvent)GetProcAddress(module, "PostInit");

                        if (init)
                            init(ModsInfo);
                        if (postInit)
                            postEvents.push_back(postInit);

                        RegisterEvent(modTickEvents, module, "OnFrame");
                        RegisterEvent(modExitEvents, module, "OnExit");
                    }
                    else
                    {
                        DWORD error = GetLastError();
                        LPSTR msgBuffer = nullptr;

                        DWORD msgSize = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msgBuffer, 0, NULL);

                        std::string msg = "Failed to load " + dllName + "\n" + std::string(msgBuffer, msgSize);
                        MessageBoxA(NULL, msg.c_str(), "HE2ModLoader", MB_OK);

                        LocalFree(msgBuffer);
                    }
                }
            }
        }
    }

    SetCurrentDirectoryA(exeDir.c_str());

    for (auto& value : ReplaceDirs)
    {
        auto root = string(value).substr(0, strlen(value) - 1);
        IndexInclude(root, root.length() + 1);
    }

    if (SupportsSaveRedirection() && useSaveFilePath)
        PrintDebug("Save file path is %s", saveFilePath->c_str());

    for (ModInitEvent event : postEvents)
        event(ModsInfo);
    for (auto string : strings)
        delete string;

    // Init CommonLoader
    PrintInfo("Loading Codes...");
    CommonLoader::LoadAssembly((GetDirectoryPath(ModsDbIniPath) + "Codes.dll").c_str());
    CommonLoader::RaiseInitializers();

    PrintInfo("Finished loading mods");
}

std::string GetHostModuleName()
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    return GetFileName(path, true);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HookSystemDLL(hModule);

        // Detach if Sonic Generations (2024).
        // TODO: load HE1ML instead.
        if (GetHostModuleName() == "SONIC_GENERATIONS")
            break;

        LoadConfig();

        if (!LoaderEnabled)
            break;

        if (!SaveFileFallback.empty())
        {
            saveFilePath->clear();
            saveFilePath->append(SaveFileFallback);
        }

        if (!SaveFileOverride.empty())
        {
            saveFilePath->clear();
            saveFilePath->append(SaveFileOverride);
        }

        useSaveFilePath = EnableSaveFileRedirection != 0;

        PrintInfo("Starting HE2ModLoader v%s...", ML_VERSION);

        // Detect Epic
        if (PROC_ADDRESS("EOSSDK-Win64-Shipping.dll", "EOS_Initialize"))
            CurrentPlatform = Platform_Epic;

        switch (CurrentPlatform)
        {
            case Platform_Steam:
                INSTALL_HOOK(SteamAPI_RestartAppIfNecessary);
                INSTALL_HOOK(SteamAPI_IsSteamRunning);
                INSTALL_HOOK(SteamAPI_Shutdown);
                break;

            case Platform_Epic:
                INSTALL_HOOK(EOS_Initialize);
                INSTALL_HOOK(EOS_Shutdown);
                break;
        }

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

