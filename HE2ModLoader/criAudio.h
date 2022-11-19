#pragma once
#include "loader.h"
#include <unordered_map>

typedef BOOL __fastcall ReadFileType(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

struct CriAudioStream
{
	unsigned short id;
	unsigned int fileSize;
	unsigned int fileOffset;
	unsigned int emulatedAddress;
	HANDLE fileHandle;
};

class CriAudio
{
protected:
	HANDLE awbHandle;
	string basePath;
	LONG awbPosition;
	char header[0x2000];
	int headerSize;
	unsigned short subkey;
	vector<CriAudioStream> streamList;
public:
	CriAudio(string path, HANDLE handle);
	~CriAudio();
	void ParseAFS2Archive(string filePath);
	int GenerateHeader();
	void* GetHeader();
	int GetHeaderSize();
	const string& GetName() const;
	const vector<CriAudioStream>& GetStreams() const;
	void ReplaceAudio(int id, HANDLE hcaHandle);
	void SetAWBHandle(HANDLE handle);
	HANDLE GetAWBHandle() const;
	void SetAWBPosition(LONG position, bool relative);
	bool ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer, ReadFileType readFile);
};

class CriACBPatcher
{
protected:
	HANDLE handle;
	string basePath;
	LONG currentPosition;
	LONG awbHeaderPosition;
	char awbHeader[0x2000];
	int awbHeaderSize;
public:
	CriACBPatcher(string path, HANDLE handle);
	void ParseACBFile();
	void LoadCriAudio(CriAudio* audio);
	void SetHandle(HANDLE handle);
	HANDLE GetHandle() const;
	void SetPosition(LONG position, bool relative);
	bool ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer);
};

extern std::unordered_map<HANDLE, std::shared_ptr<CriAudio>> CriAudios;
extern std::unordered_map<HANDLE, std::shared_ptr<CriACBPatcher>> CriACBPatchers;

void InitCriAudio();