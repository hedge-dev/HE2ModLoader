#include "pch.h"
#include "cri.h"
#include "loader.h"
#include <string>
#include <detours.h>
#include <algorithm>
#include "helpers.h"
#include "sigscanner.h"

using std::string;

CriFsBindId DirectoryBinderID = NULL;

// Signatures
DEFINE_SIGSCAN(criFsIoWin_Exists,         "\x48\x89\x5C\x24\x00\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x84\x24\x00\x00\x00\x00\x48\x8B\xDA\x48\x8B\xF9\x48\x85\xC9", "xxxx?xxxx????xxx????xxxxxxx????xxxxxxxxx")
DEFINE_SIGSCAN(criFsIoWin_Exists2,        "\x48\x89\x5C\x24\x00\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xDA\x48\x8B\xF9\x48\x85\xC9\x74\x64\x48\x85\xD2\x74\x5F\x83\x3D\x00\x00\x00\x00\x00\x74\x38\xE8\x00", "xxxx?xxxx????xxxxxxxxxxxxxxxxxx?????xxx?")
DEFINE_SIGSCAN(crifsiowin_CreateFile,     "\x40\x53\x55\x56\x57\x41\x54\x41\x56\x41\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x84\x24\x00\x00\x00\x00\x83\x3D\x00\x00", "xxxxxxxxxxxxxx????xxx????xxxxxxx????xx??")
DEFINE_SIGSCAN(crifsiowin_CreateFile2,    "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x81\xEC\x00\x00\x00\x00\x83\x3D\x00\x00\x00\x00\x00\x49\x8B\xF9\x41\x8B\xF0\x8B\xEA\x48\x8B", "xxxx?xxxx?xxxx?xxxx????xx?????xxxxxxxxxx")
DEFINE_SIGSCAN(criErr_Notify,             "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x30\x45\x33\xC9\x48\x8B\xFA\x4C\x39\x0D\x00\x00\x00\x00\x8B\xF1", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx????xx")
DEFINE_SIGSCAN(criErr_Notify2,            "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x57\x41\x56\x41\x57\x48\x83\xEC\x30\x4C\x8D\x70\xD8\x4C\x8D\x78\xD8\x48\x8B\xEA\x8B\xF9\x4C\x89\x40", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
DEFINE_SIGSCAN(criFsBinder_BindDirectory, "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x54\x41\x56\x41\x57\x48\x83\xEC\x30\x48\x8B\x74\x24\x00\x33\xED\x49\x8B\xD9\x4D", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?xxxxxx")
DEFINE_SIGSCAN(criFsBinder_BindCpk,       "\x48\x83\xEC\x48\x48\x8B\x44\x24\x00\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x89\x44\x24\x00\x8B\x44\x24\x70\x89\x44\x24\x20\xE8\x00\x00\x00\x00\x48\x83\xC4\x48\xC3", "xxxxxxxx?xxx?????xxxx?xxxxxxxxx????xxxxx")
DEFINE_SIGSCAN(criFsBinder_SetPriority,   "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x8B\xFA\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0\x75\x18\x8D\x58\xFE\x33\xC9\x44\x8B\xC3\x48\x8D\x15\x00\x00\x00\x00", "xxxx?xxxxxxxx????xxxxxxxxxxxxxxxxxxx????")
DEFINE_SIGSCAN(criFsBinder_SetPriority2,  "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x8B\xFA\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0\x75\x18\x8D\x58\xFE\x48\x8D\x15\x00\x00\x00\x00\x33\xC9\x44\x8B\xC3\xE8\x00\x00\x00\x00\x8B\xC3\xEB\x3E\x48\x83\x38\x00\x75\x13\x48\x8D\x15\x00\x00\x00\x00\x33\xC9\xE8\x00\x00\x00\x00\x83", "xxxx?xxxxxxxx????xxxxxxxxxxxxxx????xxxxxx????xxxxxxxxxxxxx????xxx????x")
DEFINE_SIGSCAN(criFsBinder_GetStatus,     "\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x48\x8B\xDA\x8B\xF9\x85\xC9\x74\x36\x48\x85\xD2\x74\x3C\xE8\x00\x00\x00\x00\x48\x85\xC0\x75\x0A\xC7\x03\x00\x00\x00\x00", "xxxx?xxxxxxxxxxxxxxxxxxxx????xxxxxxx????")
DEFINE_SIGSCAN(criSmpFsUtl_Alloc,         "\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x83\xF9\xE0\x77\x3C\x48\x85\xC9\xB8\x00\x00\x00\x00\x48\x0F\x44\xD8\xEB\x15\xE8\x00\x00\x00\x00\x85\xC0\x74\x25\x48\x8B", "xxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxx")

// Functions
FUNCTION_PTR(CriError, __fastcall, criFsBinder_BindDirectory, _acriFsBinder_BindDirectory, CriFsBinderHn bndrhn, CriFsBinderHn srcbndrhn, const CriChar8* path, void* work, CriSint32 worksize, CriFsBindId* bndrid);
FUNCTION_PTR(CriError, __fastcall, criFsBinder_GetStatus, _acriFsBinder_GetStatus, CriFsBindId bndrid, CriFsBinderStatus* status);
FUNCTION_PTR(CriError, __fastcall, criFsBinder_SetPriority, _acriFsBinder_SetPriority, CriFsBindId bndrid, CriSint32 priority);
FUNCTION_PTR(void*, __fastcall, criSmpFsUtl_Alloc, 0x1400950C0, CriUint32 size);
// NOTE: This is actually not criErr_NotifyGeneric
FUNCTION_PTR(void, __fastcall, criError_NotifyGeneric, _acriErr_Notify, CriErrorLevel level, const CriChar8* error_id, CriError error_no);


const char* PathSubString(const char* text)
{
    if (CurrentGame != Game_Tenpex)
        return text + 5;
    const char* result = strstr(text, "raw");
    if (result)
        return result + 4;
    return text;
}

// TODO: Add caching for Tenpex
HOOK(HANDLE, __fastcall, crifsiowin_CreateFile, _acrifsiowin_CreateFile, CriChar8* path, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, int dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    if (CurrentGame != Game_Tenpex)
    {
        string newPath = path + 5;
        std::transform(newPath.begin(), newPath.end(), newPath.begin(), ::tolower);
        auto it = FileCache.find(newPath);
        if (it != FileCache.end() && !it->second.empty())
        {
            const char* replacePath = it->second.c_str();
            PrintInfo("Loading File: %s", replacePath);
            strcpy(path, replacePath);
        }
    }
    else
    {
        // Mod Check
        DWORD attributes = -1;
        for (auto& value : ReplaceDirs)
        {
            string filePath = value;
            filePath += PathSubString(path);
            attributes = GetFileAttributesA(filePath.c_str());
            if (attributes != -1)
            {
                strcpy(path, filePath.c_str());
                PrintInfo("Loading File: %s", path);
                break;
            }
        }
    }
    return originalcrifsiowin_CreateFile(path, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// TODO: Add caching for Tenpex
//DataPointer(bool, crifsiowin_utf8_path, ASLR(0x142E54748));
HOOK(CriError, __fastcall, criFsIoWin_Exists, _acriFsIoWin_Exists, CriChar8* path, bool* exists)
{
    if (CurrentGame != Game_Tenpex)
    {
        *exists = false;
        string newPath = path + 5;
        std::transform(newPath.begin(), newPath.end(), newPath.begin(), ::tolower);
        auto it = FileCache.find(newPath);
        if (it != FileCache.end())
        {
            strcpy(path, it->second.c_str());
            *exists = true;
        }
    }
    else
    {
        DWORD attributes = -1;
        for (auto& value : ReplaceDirs)
        {
            string filePath = value;
            filePath += PathSubString(path);
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
            // TODO: Add proper UTF8 support
            //if (crifsiowin_utf8_path)
            //{
            //    WCHAR buffer[PATH_LIMIT];
            //    MultiByteToWideChar(65001, 0, path, strlen(path) + 1, buffer, PATH_LIMIT);
            //    attributes = GetFileAttributesW(buffer);
            //}
            //else
            //{
            attributes = GetFileAttributesA(path);
            //}
            *exists = attributes != -1 && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
        }
        else if (!*exists)
        {
            criError_NotifyGeneric(CRIERR_LEVEL_ERROR, "E2015091137", CRIERR_INVALID_PARAMETER);
            return CRIERR_NG;
        }
    }
    return CRIERR_OK;
}

HOOK(void, __fastcall, criErr_Notify, _acriErr_Notify, CriErrorLevel level, const CriChar8* error_id, CriUintPtr p1, CriUintPtr p2)
{
    std::string ss;
    ss.append("[criErr_Notify] Level: %d - ");
    ss.append(error_id);
    if (level == CRIERR_LEVEL_WARNING)
        PrintWarn((char*)ss.c_str(), level, p1, p2);
    else
        PrintError((char*)ss.c_str(), level, p1, p2);
}

HOOK(CriError, __fastcall, criFsBinder_BindCpk, _acriFsBinder_BindCpk, CriFsBinderHn bndrhn, CriFsBinderHn srcbndrhn, const CriChar8* path, void* work, CriSint32 worksize, CriFsBindId* bndrid)
{
    // Tenpex does not require binding
    if (!DirectoryBinderID && CurrentGame != Game_Tenpex)
    {
        PrintDebug("Binding directory...");
        void* dirbndr_work = work;
        // TODO: This should be freed
        if (_acriSmpFsUtl_Alloc)
            dirbndr_work = criSmpFsUtl_Alloc(88);
        criFsBinder_BindDirectory(bndrhn, nullptr, "wars", dirbndr_work, 88, &DirectoryBinderID);
        CriFsBinderStatus status = CRIFSBINDER_STATUS_ANALYZE;
        while (status != CRIFSBINDER_STATUS_COMPLETE)
        {
            criFsBinder_GetStatus(DirectoryBinderID, &status);
            if (status == CRIFSBINDER_STATUS_ERROR)
                PrintError("Failed to bind! Mod loading may fail!");
            Sleep(10);
        }
        criFsBinder_SetPriority(DirectoryBinderID, 70000000);
        PrintDebug("Directory bind completed");
    }
    PrintDebug("Binding CPK: \"%s\"", path);
    return originalcriFsBinder_BindCpk(bndrhn, srcbndrhn, path, work, worksize, bndrid);
}

void InitLoaderCri()
{
    DO_SIGSCAN(criFsIoWin_Exists2);
    DO_SIGSCAN(crifsiowin_CreateFile2);
    DO_SIGSCAN(criErr_Notify2);
    DO_SIGSCAN(criFsBinder_BindDirectory);
    DO_SIGSCAN(criFsBinder_BindCpk);
    DO_SIGSCAN(criFsBinder_SetPriority2);
    DO_SIGSCAN(criFsBinder_GetStatus);
    DO_SIGSCAN(criSmpFsUtl_Alloc);

    // Scan other variants 
    if (!_acriFsIoWin_Exists2)
        DO_SIGSCAN(criFsIoWin_Exists);
    if (!_acrifsiowin_CreateFile2)
        DO_SIGSCAN(crifsiowin_CreateFile);
    if (!_acriErr_Notify2)
        DO_SIGSCAN(criErr_Notify);
    if (!_acriFsBinder_SetPriority2)
        DO_SIGSCAN(criFsBinder_SetPriority);

    // Link scans
    LINK_SCAN(criErr_Notify, criErr_Notify2);
    LINK_SCAN(crifsiowin_CreateFile, crifsiowin_CreateFile2);
    LINK_SCAN(criFsIoWin_Exists, criFsIoWin_Exists2);
    LINK_SCAN(criFsBinder_SetPriority, criFsBinder_SetPriority2);

    // Check scans
    CHECK_SCAN(criFsIoWin_Exists);
    CHECK_SCAN(crifsiowin_CreateFile);
    CHECK_SCAN(criErr_Notify);
    CHECK_SCAN(criFsBinder_BindDirectory);
    CHECK_SCAN(criFsBinder_BindCpk);
    CHECK_SCAN(criFsBinder_SetPriority);
    CHECK_SCAN(criFsBinder_GetStatus);
    // TODO: Find musashi signatures
    CHECK_SCAN_OPT(criSmpFsUtl_Alloc);

    // Install hooks
    INSTALL_HOOK_SIG(crifsiowin_CreateFile);
    INSTALL_HOOK_SIG(criFsIoWin_Exists);
    INSTALL_HOOK_SIG(criErr_Notify);
    INSTALL_HOOK_SIG(criFsBinder_BindCpk);

    // Update function pointers
    UPDATE_FUNCTION_POINTER(criFsBinder_BindDirectory, _acriFsBinder_BindDirectory);
    UPDATE_FUNCTION_POINTER(criFsBinder_GetStatus, _acriFsBinder_GetStatus);
    UPDATE_FUNCTION_POINTER(criFsBinder_SetPriority, _acriFsBinder_SetPriority);
    UPDATE_FUNCTION_POINTER(criError_NotifyGeneric, _acriErr_Notify);
    UPDATE_FUNCTION_POINTER(criSmpFsUtl_Alloc, _acriSmpFsUtl_Alloc);
}