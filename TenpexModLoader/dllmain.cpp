// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>
#include <vector>
#include <sstream>
#include <TenpexModLoader.h>
#include <CommonLoader.h>
#include <INIReader.h>
#include <detours.h>
#include "helpers.h"
#include "Events.h"
#include <d3d11.h>

#pragma comment(linker, "/EXPORT:D3D11CreateDevice=C:\\Windows\\System32\\d3d11.D3D11CreateDevice")
#pragma comment(linker, "/EXPORT:D3D11CoreCreateDevice=C:\\Windows\\System32\\d3d11.D3D11CoreCreateDevice")
#pragma comment(linker, "/EXPORT:D3D11CreateDeviceAndSwapChain=C:\\Windows\\System32\\d3d11.D3D11CreateDeviceAndSwapChain")

#define FOREGROUND_WHITE (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)

using std::string;
using std::wstring;
using std::vector;

static vector<char*> ReplaceDirs;
static bool ConsoleEnabled = false;
static bool ProtectionBypassed = false;
static HANDLE stdoutHandle = nullptr;
intptr_t BaseAddress = (intptr_t)GetModuleHandle(nullptr);
ModInfo* ModsInfo;


static void PrintError(const char* text, ...)
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
    printf("%s%s\n", "[TenpexML] [ERROR] ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

static void PrintWarn(const char* text, ...)
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
    printf("%s%s\n", "[TenpexML] [WARN]  ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

static void PrintDebug(const char* text, ...)
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
    printf("%s%s\n", "[TenpexML] [DEBUG] ", buffer);
    SetConsoleTextAttribute(stdoutHandle, FOREGROUND_WHITE);
    va_end(ap);
}

static void PrintInfo(const char* text, ...)
{
    if (!ConsoleEnabled)
        return;
    va_list ap;
    va_start(ap, text);
    if (!stdoutHandle)
        stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[512];
    _vsprintf_p(buffer, 512, text, ap);
    printf("%s%s\n", "[TenpexML] [INFO]  ", buffer);
    va_end(ap);
}

void InitMods();
void InitLoader();

HOOK(bool, __fastcall, SteamAPI_RestartAppIfNecessary, PROC_ADDRESS("steam_api.dll", "SteamAPI_RestartAppIfNecessary"), uint32_t appid)
{
    originalSteamAPI_RestartAppIfNecessary(appid);
    std::ofstream ofs("steam_appid.txt");
    ofs << appid;
    ofs.close();
    return false;
}

HOOK(bool, __fastcall, SteamAPI_IsSteamRunning, PROC_ADDRESS("steam_api.dll", "SteamAPI_IsSteamRunning"))
{
    originalSteamAPI_IsSteamRunning();
    return true;
}

HOOK(__int64, __fastcall, INITTEST, ASLR(0x1400A0C20), unsigned int a1, __int64 a2)
{
    InitMods();
    return originalINITTEST(a1, a2);
}

HOOK(void, __fastcall, SteamAPI_Shutdown, PROC_ADDRESS("steam_api.dll", "SteamAPI_Shutdown"))
{
    RaiseEvents(modExitEvents);
    originalSteamAPI_Shutdown();
}

HOOK(HRESULT, __fastcall, SteamProtectionHook, PROC_ADDRESS("d3d11.dll", "D3D11CreateDevice"),
    IDXGIAdapter* pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software,
    UINT Flags, const D3D_FEATURE_LEVEL* pFeatureLevels, UINT FeatureLevels,
    UINT SDKVersion, ID3D11Device** ppDevice, D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext)
{
    if (!ProtectionBypassed)
    {
        PrintInfo("Attempting Steam protection bypass...");
        InitLoader();
        InitMods();
        ProtectionBypassed = true;
    }
    return originalSteamProtectionHook(pAdapter, DriverType, Software,
        Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice,
        pFeatureLevel, ppImmediateContext);
}

void GetModDirectoryFromCPKREDIR(char* buffer)
{
    PrintDebug("Loading CPKREDIR Config...");
    INIReader cpkredir("cpkredir.ini");
    auto str = cpkredir.GetString("CPKREDIR", "ModsDbIni", "mods\\ModsDB.ini");
    str = str.substr(0, str.find_last_of("\\"));
    strcpy_s(buffer, MAX_PATH, str.c_str());
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

const char* SubStringRaw(const char* text)
{
    const char* result = strstr(text, "raw");
    if (result)
        return result + 4;
    return text;
}

FastcallFunctionPointer(void, criError_NotifyGeneric, (CriErrorLevel level, const CriChar8* error_id, CriError error_no), ASLR(0x140522E48));

HOOK(CriError, __fastcall, crifsiowin_CreateFile, ASLR(0x140539614), CriChar8* path, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, int dwFlagsAndAttributes, __int64 hTemplateFile)
{
    const CriChar8* internalPath = SubStringRaw(path);
    // Mod Check
    DWORD attributes = -1;
    for (auto& value : ReplaceDirs)
    {
        string filePath = value;
        filePath += internalPath;
        attributes = GetFileAttributesA(filePath.c_str());
        if (attributes != -1)
        {
            strcpy(path, filePath.c_str());
            PrintInfo("Loading File: %s", path);
            break;
        }
    }

    return originalcrifsiowin_CreateFile(path, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DataPointer(bool, crifsiowin_utf8_path, ASLR(0x141F3D668));
HOOK(CriError, __fastcall, criFsIoWin_Exists, ASLR(0x140538F68), CriChar8* path, bool* exists)
{
    const CriChar8* internalPath = SubStringRaw(path);
    DWORD attributes = -1;
    for (auto& value : ReplaceDirs)
    {
        string filePath = value;
        filePath += internalPath;
        attributes = GetFileAttributesA(filePath.c_str());
        if (attributes != -1)
        {
            strcpy(path, filePath.c_str());
            *exists = true;
            break;
        }
    }

    if (path && attributes == -1)
    {
        if (crifsiowin_utf8_path)
        {
            WCHAR buffer[MAX_PATH];
            MultiByteToWideChar(65001, 0, path, strlen(path) + 1, buffer, MAX_PATH);
            attributes = GetFileAttributesW(buffer);
        }
        else
        {
            attributes = GetFileAttributesA(path);
        }
        *exists = attributes != -1 && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
    }
    else if (!*exists)
    {
        criError_NotifyGeneric(CRIERR_LEVEL_ERROR, "E2015091137", CRIERR_INVALID_PARAMETER);
        return CRIERR_NG;
    }
    return originalcriFsIoWin_Exists(path, exists);
}

HOOK(void, __fastcall, CriErr_NotifyGeneric, ASLR(0x140522E48), CriErrorLevel level, const CriChar8* error_id, CriError error_no)
{
    std::string ss;
    ss.append("[criErr_NotifyGeneric] Level: %d - ");
    ss.append(error_id);
    if (level == CRIERR_LEVEL_WARNING)
        PrintWarn((char*)ss.c_str(), level);
    else
        PrintError((char*)ss.c_str(), level);
}

HOOK(void*, __fastcall, RunCore, ASLR(0x14049A8A0), void* a1)
{
    void* result = originalRunCore(a1);
    RaiseEvents(modFrameEvents);
    CommonLoader::CommonLoader::RaiseUpdates();
    return result;
}

void InitLoader()
{
    INSTALL_HOOK(SteamAPI_RestartAppIfNecessary);
    INSTALL_HOOK(SteamAPI_IsSteamRunning);
    INSTALL_HOOK(SteamAPI_Shutdown);

    INSTALL_HOOK(INITTEST);

    INSTALL_HOOK(crifsiowin_CreateFile);
    INSTALL_HOOK(criFsIoWin_Exists);
    INSTALL_HOOK(CriErr_NotifyGeneric);
    INSTALL_HOOK(RunCore);
}

void InitMods()
{
    PrintDebug("Loading ModsDB...");
    ModsInfo = new ModInfo();
    ModsInfo->ModList = new vector<Mod*>();
    
    char modsDir[MAX_PATH];
    GetModDirectoryFromCPKREDIR(modsDir);
    INIReader ini((string(modsDir) + "\\ModsDB.ini").c_str());
    
    char pathbuf[MAX_PATH];
    GetModuleFileNameA(NULL, pathbuf, MAX_PATH);
    string exePath(pathbuf);
    string exeDir = exePath.substr(0, exePath.find_last_of("\\"));

    vector<ModInitEvent> postEvents;

    PrintInfo("Loading Mods...");
    int modCount = ini.GetInteger("Main", "ActiveModCount", 0);
    bool reverse = ini.GetBoolean("Main", "ReverseLoadOrder", false);

    if (reverse)
        PrintInfo("Mods will now be loaded in Reverse!");
    for (int i = (reverse ? (modCount - 1) : 0); CompareModCount(i, modCount, reverse); InDecrease(&i, reverse))
    {
        char key[14];
        snprintf(key, sizeof(key), "ActiveMod%u", i);

        auto modKey = ini.GetString("Main", string(key), "");
        if (modKey.empty())
        {
            PrintError("Invalid key mod detected in ModsDB! \"%s\"", key);
            continue;
        }

        string path = ini.GetString("Mods", modKey, "");
        string dir = path.substr(0, path.find_last_of("\\")) + "\\";
        std::replace(path.begin(), path.end(), '/', '\\');

        INIReader modConfig(path);

        auto errorLine = modConfig.ParseError();
        if (errorLine != 0)
        {
            PrintError("Failed to load mod at \"%s\"", path.c_str());
            PrintError("    at %d", errorLine);
        }
        else
        {
            const string mod_nameA = modConfig.GetString("Desc", "Title", "");
            PrintInfo("Loading Mod %d. %s", i, mod_nameA.c_str());

            int dirs = modConfig.GetInteger("Main", "IncludeDirCount", -1);
            if (dirs == -1)
                continue;

            for (unsigned int i = 0; i < dirs; i++)
            {
                char key2[14];
                snprintf(key2, sizeof(key2), "IncludeDir%u", i);
                auto path = modConfig.GetString("Main", string(key2), "");
                if (path.empty())
                    break;

                SetCurrentDirectoryA(dir.c_str());
                SetCurrentDirectoryA(path.c_str());
                char* buffer2 = new char[MAX_PATH];
                GetCurrentDirectoryA(MAX_PATH, buffer2);
                string* replacedir = new string(buffer2);
                (*replacedir) += "\\raw\\";
                PrintDebug("    Added Include: %s", replacedir->c_str());
                ReplaceDirs.insert(ReplaceDirs.begin(), (char*)replacedir->c_str());
            }

            // Check if the mod has a DLL file.
            auto dllFile = modConfig.GetString("Main", "DLLFile", "");
            if (!dllFile.empty())
            {
                SetDllDirectoryA(dir.c_str());
                SetCurrentDirectoryA(dir.c_str());
                std::stringstream stream(dllFile);
                string dllName;
                while (std::getline(stream, dllName, ','))
                {
                    if (ConsoleEnabled)
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

                        RegisterEvent(modFrameEvents, module, "OnFrame");
                        RegisterEvent(modExitEvents, module, "OnExit");
                    }
                    else
                    {
                        DWORD error = GetLastError();
                        LPSTR msgBuffer = nullptr;

                        DWORD msgSize = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msgBuffer, 0, NULL);

                        std::string msg = "Failed to load " + dllName + "\n" + std::string(msgBuffer, msgSize);
                        MessageBoxA(NULL, msg.c_str(), "TenpexModLoader", MB_OK);

                        LocalFree(msgBuffer);
                    }
                }
            }
        }
        SetCurrentDirectoryA(exeDir.c_str());
        for (ModInitEvent event : postEvents)
            event(ModsInfo);
    }

    // Init CommonLoader
    PrintInfo("Loading Codes...");
    CommonLoader::CommonLoader::InitializeAssemblyLoader((string(modsDir) + "\\Codes.dll").c_str());
    CommonLoader::CommonLoader::RaiseInitializers();

    PrintInfo("InitMods() Completed");
}

static const uint8_t GameCheck[] = { 0xE8u, 0xCEu, 0x6D, 0x36, 0x00u };

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    INIReader cpkredir;

    bool useFileLogging = false;
    string logType, logFile;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        cpkredir = INIReader("cpkredir.ini");

        logType = cpkredir.GetString("CPKREDIR", "LogType", "");
        logFile = cpkredir.GetString("CPKREDIR", "LogFile", "cpkredir.log");
        if (!logType.empty())
        {
            ConsoleEnabled = !strcmp(logType.c_str(), "console");
            useFileLogging = !strcmp(logType.c_str(), "file");
        }

        if (ConsoleEnabled)
        {
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
        }
        if (useFileLogging)
        {
            freopen(logFile.c_str(), "w", stdout);
            ConsoleEnabled = true;
        }

        PrintInfo("Starting TenpexModLoader %s...", "v1.0.1");
        if (!memcmp(GameCheck, (const char*)(ASLR(0x1400A0D14)), sizeof(GameCheck)))
            InitLoader();
        else
            INSTALL_HOOK(SteamProtectionHook);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

