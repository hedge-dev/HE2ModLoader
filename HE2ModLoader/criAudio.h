#pragma once
#include "loader.h"
#include <unordered_map>


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
	HANDLE mainAwbHandle;
	string basePath;
	LONG awbPosition;
	char header[0x2000];
	int headerSize;
	unsigned short subkey;
	vector<CriAudioStream> streamList;
public:
	CriAudio(string path, HANDLE handle);
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
	bool ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer);
};

extern std::unordered_map<HANDLE, std::unique_ptr<CriAudio>> CriAudios;

void InitCriAudio();