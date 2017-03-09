#include "LoadNtDriver.h"

WCHAR CLoadNtDriver::m_wzDriverServiceName[MAX_PATH] = { 0 };

CLoadNtDriver::CLoadNtDriver()
{
}


CLoadNtDriver::~CLoadNtDriver()
{
}

BOOL CLoadNtDriver::LoadNtDriver(std::wstring wstrDriverFullPath)
{
	if (wstrDriverFullPath.empty())
	{
		PRINTINFO("��������������·������������");
		return FALSE;
	}
	
	WCHAR   wzDriverPath[MAX_PATH] = { 0 };
	WCHAR   wzDriverFileName[MAX_PATH] = { 0 };
	BOOL    bOk = FALSE;
	ULONG32 ReturnLength = 0;

	// GetFullPathName �����ú������� ����������/��������·��������
	ReturnLength = GetFullPathName(wstrDriverFullPath.c_str(), MAX_PATH, wzDriverPath, NULL);
	if (wcscmp(wzDriverPath, L"") == 0)
	{
		PRINTERRORINFO("�޷��õ���������·��", GetLastError());
		return FALSE;
	}
	
	// ���·���Ƿ�Ϸ� ����
	if (PathIsDirectory(wzDriverPath))
	{
		PRINTINFO("�õ���·�������ǺϷ�·����");
		return FALSE;
	}

	if (!PathFileExists(wzDriverPath))
	{
		PRINTINFO("�õ���·��������");
		return FALSE;
	}

	_wsplitpath(wstrDriverFullPath.c_str(), NULL, NULL, wzDriverFileName, NULL);
	
	// �������������
	SC_HANDLE SCManagerHandle = NULL;
	SC_HANDLE NtDriverServiceHandle = NULL;
	
	DWORD dwErrorCode = 0;
	
	// ��SCM
	SCManagerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (SCManagerHandle == NULL)
	{
		PRINTERRORINFO("��SCMʧ��", GetLastError());
		goto ERROR_EXIT;
	}

	ZeroMemory(m_wzDriverServiceName, MAX_PATH);
	StrCpyW(m_wzDriverServiceName, wzDriverFileName);
	StrCatW(m_wzDriverServiceName, L"Service");
	WCHAR wzServiceShowName[MAX_PATH] = { 0 };
	swprintf_s(wzServiceShowName, (wstring(wzDriverFileName) + L"Show").c_str());

	printf("Service:%S,Show:%S,ImagePath:%S\r\n", m_wzDriverServiceName, wzServiceShowName, wzDriverPath);

	// �������� 
	NtDriverServiceHandle = CreateServiceW(SCManagerHandle, m_wzDriverServiceName, wzServiceShowName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, wzDriverPath, NULL, NULL, NULL, NULL, NULL);
	if (NtDriverServiceHandle == NULL)
	{
		dwErrorCode = GetLastError();
		if (dwErrorCode != ERROR_IO_PENDING && dwErrorCode != ERROR_SERVICE_EXISTS)
		{
			PRINTERRORINFO("������������ʧ��", dwErrorCode);
			goto ERROR_EXIT;
		}
		else
		{
			// �����Ѿ����� - ֻ��Ҫ����
			NtDriverServiceHandle = OpenService(SCManagerHandle, m_wzDriverServiceName, SERVICE_ALL_ACCESS);
			if (NtDriverServiceHandle == NULL)
			{
				PRINTERRORINFO("����������ʧ��", GetLastError());
				goto ERROR_EXIT;
			}
		}
	}
	
	// ��������
	bOk = StartService(NtDriverServiceHandle, NULL, NULL);
	if (!bOk)
	{
		dwErrorCode = GetLastError();

		if (dwErrorCode == ERROR_IO_PENDING)
		{
			PRINTINFO("���������޷�����");
			goto ERROR_EXIT;
		}
		else if (dwErrorCode == ERROR_SERVICE_ALREADY_RUNNING)
		{
			PRINTINFO("�����Ѿ�������");
			goto ERROR_EXIT;
		}
		else
		{
			PRINTERRORINFO("������������ʧ��", dwErrorCode);
			goto ERROR_EXIT;
		}
	}

	if (SCManagerHandle != NULL)
	{
		CloseHandle(SCManagerHandle);
		SCManagerHandle = NULL;
	}

	if (NtDriverServiceHandle != NULL)
	{
		CloseHandle(NtDriverServiceHandle);
		NtDriverServiceHandle = NULL;
	}
	return TRUE;

ERROR_EXIT:
	{
		if (SCManagerHandle != NULL)
		{
			CloseHandle(SCManagerHandle);
			SCManagerHandle = NULL;
		}

		if (NtDriverServiceHandle != NULL)
		{
			CloseHandle(NtDriverServiceHandle);
			NtDriverServiceHandle = NULL;
		}
		return FALSE;
	}
}

BOOL CLoadNtDriver::LoadNtDriver(std::string strDriverFullPath)
{
	wstring wstrDriverFullPath = StringToWstring(strDriverFullPath);
	if (LoadNtDriver(wstrDriverFullPath))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CLoadNtDriver::UnloadNtDriver(std::wstring wstrDriverServiceName)
{
	SC_HANDLE SCManagerHandle = NULL;
	SC_HANDLE NtDriverServiceHandle = NULL;
	BOOL	  bOk = TRUE;
	SERVICE_STATUS ServiceStatus = { 0 };


	SCManagerHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (SCManagerHandle == NULL)
	{
		PRINTERRORINFO("�򿪷��������ʧ��", GetLastError());
		bOk = FALSE;
		goto ERROR_EXIT;
	}

	NtDriverServiceHandle = OpenService(SCManagerHandle, wstrDriverServiceName.c_str(), SC_MANAGER_ALL_ACCESS);
	if (NtDriverServiceHandle == NULL)
	{
		PRINTERRORINFO("����������ʧ��", GetLastError());
		bOk = FALSE;
		goto ERROR_EXIT;
	}

	if (!ControlService(NtDriverServiceHandle, SERVICE_CONTROL_STOP, &ServiceStatus))
	{
		PRINTERRORINFO("ֹͣ��������ʧ��", GetLastError());
		bOk = FALSE;
		goto ERROR_EXIT;
	}

	if (!DeleteService(NtDriverServiceHandle))
	{
		PRINTERRORINFO("ɾ����������ʧ��", GetLastError());
		bOk = FALSE;
		goto ERROR_EXIT;
	}

ERROR_EXIT:
	{
		if (SCManagerHandle != NULL)
		{
			CloseHandle(SCManagerHandle);
			SCManagerHandle = NULL;
		}

		if (NtDriverServiceHandle != NULL)
		{
			CloseHandle(NtDriverServiceHandle);
			NtDriverServiceHandle = NULL;
		}
		return bOk;
	}
}

BOOL CLoadNtDriver::UnloadNtDriver(std::string strDriverServiceName)
{
	wstring wstrDriverServiceName = StringToWstring(strDriverServiceName);
	if (UnloadNtDriver(wstrDriverServiceName))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

void CLoadNtDriver::ShowErrorInfo(ULONG32 ulErrorCode, LPCTSTR pFuncName, ULONG32 ulLine, ULONG ulType)
{

}



std::wstring StringToWstring(const std::string& str)
{
	ULONG ulLength = 0;

	if (!str.empty())
	{
		ulLength = MultiByteToWideChar(CP_ACP, NULL, str.c_str(), -1, NULL, 0);

		if (ulLength > 0)
		{
			std::wstring wstr(ulLength + 1, '\0');
			MultiByteToWideChar(CP_ACP, NULL, str.c_str(), -1, &wstr[0], ulLength);
			return wstr;
		}
	}

	return NULL;
}