/*
*	MyDll���ù��ܺ���
*	�ް�Ȩ��ӭ�����޸�
*	http://www.kusoft.org
*  By Wt0x00  Make:2007
*/
#include "MyDll.h"
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

/******************************************************
�����������������̵�Ȩ��;
����˵����1.PrivilegeName:Ҫ����Ȩ�޵�����;
******************************************************/
bool WINAPI EnablePrivilege(LPCWSTR PrivilegeName)
{
	HANDLE hProc, hToken;
	TOKEN_PRIVILEGES TP;
	//��ý��̾��;
	hProc = GetCurrentProcess();
	//�򿪽������ƻ�;
	if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return false;
	}
	//��ý��̱���ΨһID;
	if (!LookupPrivilegeValue(NULL, PrivilegeName, &TP.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TP.PrivilegeCount = 1;
	//����Ȩ��;
	if (!AdjustTokenPrivileges(hToken, false, &TP, sizeof(TP), 0, 0))
	{
		CloseHandle(hToken);
		return false;
	}
	CloseHandle(hToken);
	return true;
}

//����;
int ReComputer()
{
	DWORD dwVersion = GetVersion();
	//�ж�ϵͳ�İ汾;
	//Windows 2000/XP/2003����Ҫ�������̵ļ���;
	if (dwVersion < 0x80000000)
	{
		if (EnablePrivilege(SE_SHUTDOWN_NAME))
		{
			return(ExitWindowsEx(EWX_SHUTDOWN | EWX_REBOOT, 0));
		}
	}
	else
	{
		return(ExitWindowsEx(EWX_SHUTDOWN | EWX_REBOOT, 0));
	}
	return 0;
}

//�ػ�;
int CloseComputer()
{
	DWORD dwVersion = GetVersion();
	if (dwVersion < 0x80000000)
	{
		if (EnablePrivilege(SE_SHUTDOWN_NAME))
		{
			return(ExitWindowsEx(EWX_SHUTDOWN | EWX_POWEROFF, 0));
		}
	}
	else
	{
		return(ExitWindowsEx(EWX_SHUTDOWN | EWX_REBOOT, 0));
	}
	return 0;
}

/******************************************************
�������������ҽ��̲��ҷ��������ID;
����˵����1.lpszProcess:Ҫ���ҵĽ�����;
******************************************************/
DWORD FindProcessId(WCHAR* lpszProcess)
{
	DWORD dwRet = 0;
	//�������̿���;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//������Ϣ���ݽṹ;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//�õ����յ�һ��������Ϣ;
	Process32First(hSnapshot, &pe32);
	do
	{
		_wcsupr_s(pe32.szExeFile, wcslen(pe32.szExeFile) + 1);
		_wcsupr_s(lpszProcess, wcslen(lpszProcess) + 1);
		if (lstrcmpi(pe32.szExeFile, lpszProcess) == 0)
		{
			dwRet = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));//��ȡ��һ��;
	CloseHandle(hSnapshot);
	return dwRet;
}

/******************************************************
������������DLL���뵽ָ����Ŀ�������;
����˵����1.lpszDll��Ҫ����Ķ�̬���ӿ���;
2.lpszProcess:Ҫ����Ľ���;
����ֵ������ɹ�����TRUE������ʧ�ܷ���FALSE;
******************************************************/
bool InsertDll(LPCTSTR lpszDll, WCHAR* lpszProcess)
{
	DWORD  dwSize, dwWritten, dwRet;
	WCHAR   FilePath[MAX_PATH] = {};
	//��ȡDLL��·��;
	GetFullPathName(lpszDll, MAX_PATH, FilePath, NULL);
	dwSize = wcslen(FilePath) + 1;
	dwRet = FindProcessId(lpszProcess);
	if (0 == dwRet)
	{
		return false;
	}
	if (!EnablePrivilege(SE_DEBUG_NAME))
	{
		return false;
	}
	//�򿪽��̣���øý��̾��;
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
		, FALSE, dwRet);
	if (NULL == hProcess)
	{
		return false;
	}
	//�ڽ���������һ���ڴ�;
	LPVOID lpBuf = (LPVOID)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpBuf == NULL)
	{
		CloseHandle(hProcess);
		return false;
	}
	//��DLLд�����뵽���ڴ�;
	if (!WriteProcessMemory(hProcess, lpBuf, (LPVOID)FilePath, dwSize, &dwWritten))
	{
		if (dwWritten != dwSize)
		{
			VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT);
			CloseHandle(hProcess);
			return false;
		}
		else
			CloseHandle(hProcess);
		return false;
	}
	DWORD dwID;
	//���LoadLibraryW�����ĵ�ַ;
	LPVOID pFunc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	//����Զ���߳�;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc
		, lpBuf, 0, &dwID);
	if (hThread == NULL)
	{
		VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT);
		CloseHandle(hProcess);
		return false;
	}
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
	{
		return false;
	}
	VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return true;
}

/*-----------------------���̲�����غ���;------------------------*/
/******************************************************
��������������ָ���Ľ��̵��õĶ�̬���ӿ�;
����˵����1.exeName��Ҫ���ҵĽ�����;
����ֵ������ɹ����������ͷhead��ʧ�ܷ���NULL;
******************************************************/
pModule FindExeDll(WCHAR* exeName)
{
	PROCESSENTRY32* pInfo = new PROCESSENTRY32;
	MODULEENTRY32* dInfo = new MODULEENTRY32;
	pInfo->dwSize = sizeof(PROCESSENTRY32);
	dInfo->dwSize = sizeof(MODULEENTRY32);
	ModuleInfo *p = NULL;
	ModuleInfo *head = NULL;

	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hModule = NULL;
	EnablePrivilege(SE_DEBUG_NAME);
	Process32First(hProcess, pInfo);
	do
	{
		_wcsupr_s(exeName, wcslen(exeName) + 1);
		_wcsupr_s(pInfo->szExeFile, wcslen(pInfo->szExeFile) + 1);
		if (!wcscmp(exeName, pInfo->szExeFile))
		{
			hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pInfo->th32ProcessID);
			Module32First(hModule, dInfo);
			do
			{
				p = new ModuleInfo();
				p->th32ProcessID = dInfo->th32ProcessID;
				wcscpy_s(p->szExePath, dInfo->szExePath);
				if (head)
				{
					p->next = head->next;
					head->next = p;
				}
				else
				{
					head = p;
				}
			} while (Module32Next(hModule, dInfo));
			if (hModule)
			{
				CloseHandle(hModule);
				hModule = NULL;
			}
		}
	} while (Process32Next(hProcess, pInfo));

	if (hProcess){
		CloseHandle(hProcess);
	}
	delete pInfo;
	delete dInfo;

	return NULL;
}

/******************************************************
��������������ָ���Ķ�̬���ӿⱻ��Щ���̵���;
����˵����1.dllName��Ҫ���ҵĶ�̬���ӿ�;
����ֵ������ɹ����������ͷhead��ʧ�ܷ���NULL;
******************************************************/
pModule FindDllExe(WCHAR* dllName)
{
	PROCESSENTRY32* pInfo = new PROCESSENTRY32;
	MODULEENTRY32* dInfo = new MODULEENTRY32;
	pInfo->dwSize = sizeof(PROCESSENTRY32);
	dInfo->dwSize = sizeof(MODULEENTRY32);
	ModuleInfo *p = NULL;
	ModuleInfo *head = NULL;

	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hModule = NULL;
	EnablePrivilege(SE_DEBUG_NAME);
	Process32First(hProcess, pInfo);
	do
	{
		hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pInfo->th32ProcessID);
		Module32First(hModule, dInfo);
		WCHAR temp[MAX_PATH] = {};
		wcscpy_s(temp, dInfo->szExePath);
		do
		{
			_wcsupr_s(dllName, wcslen(dllName) + 1);
			_wcsupr_s(dInfo->szModule, wcslen(dInfo->szModule) + 1);
			if (!wcscmp(dllName, dInfo->szModule))
			{
				p = new ModuleInfo();
				p->th32ProcessID = dInfo->th32ProcessID;
				wcscpy_s(p->szExePath, temp);
				if (head)
				{
					p->next = head->next;
					head->next = p;
				}
				else
				{
					head = p;
				}
			}
		} while (Module32Next(hModule, dInfo));
		if (hModule)
		{
			CloseHandle(hModule);
			hModule = NULL;
		}
	} while (Process32Next(hProcess, pInfo));

	if (hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	delete pInfo;
	delete dInfo;

	return head;
}

/******************************************************
�����������������н��̵Ŀ���;
����ֵ������ɹ����������ͷhead��ʧ�ܷ���NULL;
******************************************************/
pModule SnapshotProcess()
{
	PROCESSENTRY32* pInfo = new PROCESSENTRY32;
	MODULEENTRY32* dInfo = new MODULEENTRY32;
	pInfo->dwSize = sizeof(PROCESSENTRY32);
	dInfo->dwSize = sizeof(MODULEENTRY32);
	ModuleInfo *p = NULL;
	ModuleInfo *head = NULL;
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	HANDLE hModule = NULL;
	EnablePrivilege(SE_DEBUG_NAME);
	Process32First(hProcess, pInfo);
	do
	{
		hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pInfo->th32ProcessID);
		Module32First(hModule, dInfo);
		p = new ModuleInfo();
		p->th32ProcessID = dInfo->th32ProcessID;
		wcscpy_s(p->szExePath, dInfo->szExePath);
		if (head)
		{
			p->next = head->next;
			head->next = p;
		}
		else
		{
			head = p;
		}
		if (hModule)
		{
			CloseHandle(hModule);
			hModule = NULL;
		}
	} while (Process32Next(hProcess, pInfo));
	if (hProcess){
		CloseHandle(hProcess);
	}
	delete pInfo;
	delete dInfo;
	return head;
}

/******************************************************
�������������ݽ���ID��������;
����˵����1.dwId������ID;
����ֵ������ɹ�����TRUE��ʧ�ܷ���FALSE;
******************************************************/
BOOL TerminateProcessFromId(DWORD dwId)
{
	BOOL bRet = FALSE;
	// ��Ŀ�����,ȡ�ý��̾��;
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);
	if (hProcess != NULL)
	{
		bRet = ::TerminateProcess(hProcess, 0);
	}
	CloseHandle(hProcess);
	return bRet;
}
/*------------------------------------------------------------*/

//��ɾ��;
void SelfDelete()
{
	TCHAR szModule[MAX_PATH],
		szComspec[MAX_PATH],
		szParams[MAX_PATH];

	//��ȡ�ļ���·���ͻ�������"COMSPEC"��ֵ��mcd·��;
	if ((GetModuleFileName(0, szModule, MAX_PATH) != 0) &&
		(GetShortPathName(szModule, szModule, MAX_PATH) != 0) &&
		(GetEnvironmentVariable(L"COMSPEC", szComspec, MAX_PATH) != 0))
	{
		//���������в���;
		lstrcpy(szParams, L" /c del ");
		lstrcat(szParams, szModule);
		lstrcat(szParams, L" > nul");
		lstrcat(szComspec, szParams);

		std::cout << szComspec << std::endl;
		//�������ݽṹ����;
		STARTUPINFO		si = { 0 };
		PROCESS_INFORMATION	pi = { 0 };
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;

		// increase resource allocation to program;
		SetPriorityClass(GetCurrentProcess(),
			REALTIME_PRIORITY_CLASS);
		SetThreadPriority(GetCurrentThread(),
			THREAD_PRIORITY_TIME_CRITICAL);

		if (CreateProcess(0, szComspec, 0, 0, 0, CREATE_SUSPENDED |
			DETACHED_PROCESS, 0, 0, &si, &pi))
		{
			SetPriorityClass(pi.hProcess, IDLE_PRIORITY_CLASS);
			SetThreadPriority(pi.hThread, THREAD_PRIORITY_IDLE);

			ResumeThread(pi.hThread);
			return;
		}
		else
		{
			SetPriorityClass(GetCurrentProcess(),
				NORMAL_PRIORITY_CLASS);
			SetThreadPriority(GetCurrentThread(),
				THREAD_PRIORITY_NORMAL);
		}
	}
	return;
}