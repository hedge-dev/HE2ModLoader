#pragma once
#include <HE2ModLoader.h>
#include <map>
#include <string>

using std::string;
using std::vector;
using std::map;

// Imports
extern intptr_t BaseAddress;
extern Game CurrentGame;
extern vector<char*> ReplaceDirs;
extern map<string, string> FileCache;
extern void PrintDebug(const char* text, ...);
extern void PrintError(const char* text, ...);
extern void PrintWarn(const char* text, ...);
extern void PrintInfo(const char* text, ...);
