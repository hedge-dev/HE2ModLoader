#include "pch.h"
#include "save.h"
#include "config.h"
#include <INIReader.h>

std::string ModsDbIniPath;
std::string SaveFileFallback;
std::string SaveFileOverride;
bool EnableSaveFileRedirection;
bool ConsoleEnabled = false;
bool LoaderEnabled;

void LoadConfig()
{
    INIReader config("cpkredir.ini");

    std::string logType = config.GetString("CPKREDIR", "LogType", "");
    std::string logFile = config.GetString("CPKREDIR", "LogFile", "cpkredir.log");
    ModsDbIniPath = config.GetString("CPKREDIR", "ModsDbIni", ".\\Mods\\ModsDB.ini");
    SaveFileFallback = config.GetString("CPKREDIR", "SaveFileFallback", "");
    SaveFileOverride = config.GetString("CPKREDIR", "SaveFileOverride", "");
    EnableSaveFileRedirection = config.GetBoolean("CPKREDIR", "EnableSaveFileRedirection", false);
    LoaderEnabled = config.GetBoolean("CPKREDIR", "Enabled", true);
    bool useFileLogging = false;

    if (!LoaderEnabled)
        return;

    // Do not use cpkredir.sav, should nolonger be needed
    if (SaveFileFallback.find("cpkredir.sav") != std::string::npos)
        SaveFileFallback = "savedata";

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
}