#define _CRT_SECURE_NO_WARNINGS
#pragma once

#include <windows.h>
#include <vector>
#include <string>

using namespace std;

class CPeParser
{
public:
	CPeParser(const char* m_pFilePath);
	~CPeParser();
	char m_pFilePath[MAX_PATH];
	byte* m_pFileBuffer;
	byte* m_pMemBuffer;

	BOOL loadFileToMem();

	DWORD m_dwImageBase;
	DWORD m_dwImageSize;
	DWORD m_dwCodeBase;
	DWORD m_dwCodeSize;
	DWORD m_dwEP;
	DWORD m_dwMemAlign;
	DWORD m_dwFileAlign;
	DWORD m_dwImportOffset;
	DWORD m_dwIATOffset;

	IMAGE_OPTIONAL_HEADER32 *m_pOptionalHead;
	IMAGE_DATA_DIRECTORY* GetDataDir();
	IMAGE_SECTION_HEADER m_SectionInfo[16] = {0};
	int m_SectionCount;

	// 0043ADCD    8907                  MOV DWORD PTR DS:[EDI],EAX               ; 对CALL指令（E8）后面的4字节进行修复
	// 0043ADCF    83C7 05               ADD EDI, 0x5
	//	0043ADD2    88D8                  MOV AL, BL
	//	0043ADD4  ^ E2 D9                 LOOPD SHORT hello15p.0043ADAF
	//	0043ADD6    8DBE 00700300         LEA EDI, DWORD PTR DS : [ESI + 0x37000]
	byte m_pbyCode1[11] = { 0x89, 0x07, 0x83, 0xc7, 0x05, 0x88, 0xd8, 0xe2, 0xd9, 0x8d, 0xbe };
	//	0043ADDC    8B07                  MOV EAX, DWORD PTR DS : [EDI]; 获取dll名称的偏移
	//	0043ADDE    09C0                  OR EAX, EAX; hello15p.0043CB35
	//	0043ADE0    74 45                 JE SHORT hello15p.0043AE27
	//	0043ADE2    8B5F 04               MOV EBX, DWORD PTR DS : [EDI + 0x4]; 获取 IAT的偏移
	//	0043ADE5    8D8430 94B90300       LEA EAX, DWORD PTR DS : [EAX + ESI + 0x3B994]
	byte m_pbyCode2[12] = { 0x8b, 0x07, 0x09, 0xc0, 0x74, 0x45, 0x8b, 0x5f, 0x04, 0x8d, 0x84, 0x30 };

	// PE标志特征
	byte m_pbyCode3[4] = { 0x50, 0x45, 0x00, 0x00 };

	// jmp OEP代码处特征 
	BYTE m_byCode[9] = { 0x6A,0x00,0x39,0xC4,0x75,0xFA,0x83,0xEC,0x80 };

	DWORD FindMem(BYTE* pbyCode, DWORD codeLen);
	DWORD FindMem2(byte* pBase, DWORD size,BYTE* pbyCode, DWORD codeLen);
	DWORD FindMem3(byte* pBase, DWORD size, BYTE* pbyCode, DWORD codeLen);

	
	DWORD parseIATAndFixImport(DWORD dwImportOffset, DWORD dwDllNameOffset);

	bool SaveFile(byte * buf, int len, const char * filename);

	void DumpMemory();
};

