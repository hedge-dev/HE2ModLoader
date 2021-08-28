#include "pch.h"
#include "wars.h"
#include <HE2ModLoader.h>
#include <string>
#include <detours.h>
#include "helpers.h"
#include "sigscanner.h"

using std::string;

// Import
extern intptr_t BaseAddress;
extern string* saveFilePath;
extern bool useSaveFilePath;
extern void PrintDebug(const char* text, ...);
extern void PrintInfo(const char* text, ...);

// NOTE: This could be a bad idea
static void* SaveHandle = 0;
// Wars uses this as the encryption key
static char SteamID[16];

// Save File
DEFINE_SIGSCAN(StreamWriterWin32_Open, "\x40\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xC2\x48\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x8B\xD9\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x8B\xC8\xC7\x44\x24\x00\x00", "xxxxx????xxxxxxx?????xxxxxx?????xxxxxx??")
DEFINE_SIGSCAN(StreamReaderWin32_Open, "\x40\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xC2\x48\xC7\x44\x24\x00\x00\x00\x00\x00\x45\x33\xC9\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x8B\xD9\xC7\x44\x24\x00\x00", "xxxxx????xxxxxxx?????xxxxxx?????xxxxxx??")
DEFINE_SIGSCAN(StreamReaderWin32_Read, "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\x01\x4C\x89\xC7\x48\x89\xD6\x48\x89\xCB\xFF\x50\x10\x84\xC0\x0F\x85\x00\x00\x00\x00\x31\xC0", "xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxxxx????xx")
DEFINE_SIGSCAN(sub_140724F60,          "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xFA\x48\x8B\xD9\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8D\x4C", "xxxx?xxxx?xxxx????xxxxxxx????xxxx????xxx")
DEFINE_SIGSCAN(sub_1406E7DF0,          "\x48\x89\x5C\x24\x00\x55\x57\x41\x56\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xD9\xC6\x05\x00\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00", "xxxx?xxxxxxxx????xxx????xxxxx?????xxx???")


void GuessSaveKey(BYTE* bytes, int* keylen, BYTE* key)
{
    const char* header = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>";
    for (int ii = 0; ii < 20; ++ii)
        for (int i = 0; i < 255; ++i)
            if ((char)(bytes[ii] ^ i) == header[ii])
                key[ii] = (BYTE)i;

    for (int i = 10; i > 5; --i)
    {
        if (!memcmp(key, key + i, i))
        {
            *keylen = i;
            key[*keylen] = 0;
            return;
        }
    }
    if (key[0] == key[10] && key[1] == key[11])
        *keylen = 10;
    if (key[0] == key[9] && key[1] == key[10])
        *keylen = 9;
    if (key[0] == key[8] && key[1] == key[9])
        *keylen = 8;
}

void CryptSave(BYTE* buffer, int bufferSize, BYTE* key, int keylen)
{
    for (int i = 0; i < bufferSize; ++i)
        buffer[i] ^= key[i % keylen];
}

void SwapKeys(BYTE* buffer, int bufferSize, BYTE* key, int keylen)
{
    BYTE keybuffer[12];
    const char* header = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>";
    memcpy(keybuffer, buffer, 12);
    CryptSave(keybuffer, sizeof(keybuffer), key, keylen);
    if (memcmp(keybuffer, header, 12))
    {
        PrintInfo("    Key change needed!");
        int oldKeylen = 0;
        BYTE oldKey[20];
        GuessSaveKey((BYTE*)buffer, &oldKeylen, oldKey);
        PrintInfo("    Key: %s -> %s", (char*)oldKey, key);
        // Decrypt
        CryptSave((BYTE*)buffer, bufferSize, oldKey, oldKeylen);
        // Encrypt
        CryptSave((BYTE*)buffer, bufferSize, key, keylen);
    }
}

HOOK(HANDLE, __fastcall, StreamWriterWin32_Open, _aStreamWriterWin32_Open, void* a1, LPCSTR filePath)
{
    if (!strcmp(filePath, saveFilePath->c_str()))
    {
        PrintInfo("Opening redirected save file for writing...");
        SaveHandle = a1;
    }
    return originalStreamWriterWin32_Open(a1, filePath);
}

HOOK(HANDLE, __fastcall, StreamReaderWin32_Open, _aStreamReaderWin32_Open, void* a1, LPCSTR filePath)
{
    if (!strcmp(filePath, saveFilePath->c_str()))
        SaveHandle = a1;

    return originalStreamReaderWin32_Open(a1, filePath);
}

HOOK(__int64, __fastcall, StreamReaderWin32_Read, _aStreamReaderWin32_Read, void* a1, BYTE* buffer, DWORD bufferSize)
{
    __int64 result = originalStreamReaderWin32_Read(a1, buffer, bufferSize);;

    if (result)
    {
        if (a1 = SaveHandle)
        {
            PrintInfo("Reading Redirected SaveFile...");
            SwapKeys(buffer, bufferSize, (BYTE*)SteamID, (int)strlen(SteamID));
        }
    }
    else
    {
        MessageBoxA(NULL, "Failed to read save file! Force closing the game is recommended!", "Save Error", NULL);
    }
    return result;
}

HOOK(void*, __fastcall, sub_140724F60, _asub_140724F60, void* a1, const char** filePath)
{
    void* result = originalsub_140724F60(a1, filePath);

    char mainSavePath[PATH_LIMIT];
    sprintf(mainSavePath, "%s%s%s", "..\\..\\..\\..\\image\\x64\\raw\\..\\..\\..\\savedata\\", SteamID, "\\savedata.xml");
    
    if (!strcmp(*filePath, mainSavePath))
    {
        if (FileExists(saveFilePath->c_str()))
            *filePath = saveFilePath->c_str();
        else
            PrintInfo("Redirected save does not exist, your main save file will be read instead!");
    }
    return result;
}

// Used to get the steam ID
HOOK(void*, __fastcall, sub_1406E7DF0, _asub_1406E7DF0, void* a1, int steamID)
{
    sprintf(SteamID, "%d", steamID);
    PrintDebug("Loaded ID: %s", SteamID);
    return originalsub_1406E7DF0(a1, steamID);
}

void InitLoaderWars()
{
    if (useSaveFilePath)
    {
        // Scan save hooks
        DO_SIGSCAN(StreamWriterWin32_Open);
        DO_SIGSCAN(StreamReaderWin32_Open);
        DO_SIGSCAN(StreamReaderWin32_Read);
        DO_SIGSCAN(sub_140724F60);
        DO_SIGSCAN(sub_1406E7DF0);

        // Check warning
        if (!_aStreamWriterWin32_Open || !_aStreamReaderWin32_Open ||
            !_aStreamReaderWin32_Read || !_asub_140724F60 || !_asub_1406E7DF0)
        {
            MessageBoxA(NULL, "One or more signatures for save redirection is missing, save redirection may not continue!", "Load Error", NULL);
            useSaveFilePath = false;
            return;
        }

        // Check scans
        CHECK_SCAN(StreamWriterWin32_Open);
        CHECK_SCAN(StreamReaderWin32_Open);
        CHECK_SCAN(StreamReaderWin32_Read);
        CHECK_SCAN(sub_140724F60);
        CHECK_SCAN(sub_1406E7DF0);

        // Install hooks
        INSTALL_HOOK_SIG(StreamWriterWin32_Open);
        INSTALL_HOOK_SIG(StreamReaderWin32_Open);
        INSTALL_HOOK_SIG(StreamReaderWin32_Read);
        INSTALL_HOOK_SIG(sub_140724F60);
        INSTALL_HOOK_SIG(sub_1406E7DF0);

        // Prepare default save path
        char savePath[PATH_LIMIT];
        strcpy(savePath, saveFilePath->c_str());
        saveFilePath->clear();
        saveFilePath->append("..\\..\\..\\..\\");
        saveFilePath->append(savePath);
    }

}