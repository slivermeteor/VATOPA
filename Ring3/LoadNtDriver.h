#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

using namespace std;

#ifdef _CONSOLE
#define PRINTINFO(Info) printf(Info);printf("\r\n");
#define PRINTERRORINFO(ErrorInfo, ErrorCode) printf(ErrorInfo);cout<<endl<<" ´íÎó´úÂë:"<<ErrorCode<<endl;
#else
#define PRINTINFO(Info) MessageBox(NULL, Info, _T("Message"), MB_OK)
#endif

class CLoadNtDriver
{
public:
	CLoadNtDriver();
	~CLoadNtDriver();

	static WCHAR m_wzDriverServiceName[MAX_PATH];

	static BOOL LoadNtDriver(std::string strDriverFullPath);
	static BOOL LoadNtDriver(std::wstring wstrDriverFullPath);

	static BOOL UnloadNtDriver(std::string strDriverServiceName);
	static BOOL UnloadNtDriver(std::wstring wstrDriverServiceName);

	static void ShowErrorInfo(ULONG32 ulErrorCode, LPCTSTR pFuncName, ULONG32 ulLine, ULONG ulType);
};

std::wstring StringToWstring(const std::string& str);