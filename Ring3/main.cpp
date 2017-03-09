#include <iostream>
#include <windows.h>
#include "LoadNtDriver.h"

using namespace std;

#define CTL_PAE \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_NEITHER, FILE_ANY_ACCESS)
#define CTL_IA32E \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_NEITHER, FILE_ANY_ACCESS)

#define DEVICE_LINK_NAME L"\\\\.\\PAENonPSEx86LinkName"
#ifndef _WIN64
#define DRIVER_NAME L"\\PAE-NONPSEx86.sys"
#else
#define DRIVER_NAME L"\\IA32E.sys"
#endif
int main()
{
	CHAR szBuffer[] = "HelloWorld!";
	ULONG_PTR InAddress = 0;
	ULONG_PTR OutAddress = 0;
	HANDLE DeviceHandle = NULL;
	CHAR* Buffer = NULL;

	/*WCHAR wzCurrentDir[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(MAX_PATH, wzCurrentDir);
	if (!CLoadNtDriver::LoadNtDriver(wstring(wzCurrentDir) + wstring(DRIVER_NAME)))
	{
		printf("加载驱动失败\r\n");
		goto ERROR_EXIT;
	}*/

	Buffer = (CHAR*)VirtualAlloc(NULL, 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(Buffer, szBuffer, 12);

	
	DeviceHandle = CreateFileW(DEVICE_LINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DeviceHandle == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Failed With Error Code:%d\r\n", GetLastError());
		goto ERROR_EXIT;
	}

	InAddress = (ULONG_PTR)Buffer;
	DWORD ReturnLength = 0;

#ifndef _WIN64
	printf("传入的虚拟地址:0x%p\r\n", (PVOID)InAddress);
	if (!DeviceIoControl(DeviceHandle, CTL_PAE, &InAddress, sizeof(ULONG32), &OutAddress, sizeof(ULONG32), &ReturnLength, NULL))
	{
		printf("DeviceIoControl Failed With Error Code:%d\r\n", GetLastError());
		goto ERROR_EXIT;
	}
	printf("传出的物理地址:0x%p\r\n", (PVOID)OutAddress);
#else
	printf("传入的虚拟地址:%#llx\r\n", InAddress);
	if (!DeviceIoControl(DeviceHandle, CTL_IA32E, &InAddress, sizeof(ULONG64), &OutAddress, sizeof(ULONG64), &ReturnLength, NULL))
	{
		printf("DeviceIoControl Failed With Error Code:%d\r\n", GetLastError());
		goto ERROR_EXIT;
	}
	printf("传出的物理地址:%#llx\r\n", OutAddress);
#endif

	ERROR_EXIT:
	{
		if (DeviceHandle != NULL)
		{
			CloseHandle(DeviceHandle);
			DeviceHandle = NULL;
		}

		if (Buffer != NULL)
		{
			VirtualFree(Buffer, 0, MEM_RELEASE);
		}
		/*if (StrCmpW(CLoadNtDriver::m_wzDriverServiceName,L"") != 0)
		{
			CLoadNtDriver::UnloadNtDriver(CLoadNtDriver::m_wzDriverServiceName);
		}*/
	}

	system("pause");
	return 0;
}