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
	vector<CriAudioStream> streamList;
public:
	CriAudio(string path);
	~CriAudio();
	void ParseAFS2Archive(string filePath);
	int GenerateHeader();
	void* GetHeader();
	int GetHeaderSize();
	vector<CriAudioStream> GetStreams();
	void ReplaceAudio(int id, HANDLE hcaHandle);
	void SetAWBHandle(HANDLE handle);
	HANDLE GetAWBHandle();
	void SetAWBPosition(LONG position, bool relative);
	bool ReadData(DWORD size, LPDWORD bytesRead, LPVOID buffer);
};

CriAudio* GetCriAudioByName(string basePath);
void InitCriAudio();