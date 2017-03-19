/*
*	MyDll常用功能函数
*	无版权欢迎任意修改
*	http://www.kusoft.org
*  By Wt0x00  Make:2007
*/
#include "MyDll.h"
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

/******************************************************
功能描述：调整进程的权限;
参数说明：1.PrivilegeName:要调整权限的名字;
******************************************************/
bool WINAPI EnablePrivilege(LPCWSTR PrivilegeName)
{
	HANDLE hProc, hToken;
	TOKEN_PRIVILEGES TP;
	//获得进程句柄;
	hProc = GetCurrentProcess();
	//打开进程令牌环;
	if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return false;
	}
	//获得进程本地唯一ID;
	if (!LookupPrivilegeValue(NULL, PrivilegeName, &TP.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return false;
	}
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TP.PrivilegeCount = 1;
	//调整权限;
	if (!AdjustTokenPrivileges(hToken, false, &TP, sizeof(TP), 0, 0))
	{
		CloseHandle(hToken);
		return false;
	}
	CloseHandle(hToken);
	return true;
}

//重启;
int ReComputer()
{
	DWORD dwVersion = GetVersion();
	//判断系统的版本;
	//Windows 2000/XP/2003的需要调整进程的级别;
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

//关机;
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
功能描述：查找进程并且返回其进程ID;
参数说明：1.lpszProcess:要查找的进程名;
******************************************************/
DWORD FindProcessId(WCHAR* lpszProcess)
{
	DWORD dwRet = 0;
	//创建进程快照;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//进程信息数据结构;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//得到快照第一个进程信息;
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
	} while (Process32Next(hSnapshot, &pe32));//获取下一个;
	CloseHandle(hSnapshot);
	return dwRet;
}

/******************************************************
功能描述：把DLL插入到指定的目标进程中;
参数说明：1.lpszDll：要插入的动态连接库名;
2.lpszProcess:要插入的进程;
返回值：插入成功返回TRUE，插入失败返回FALSE;
******************************************************/
bool InsertDll(LPCTSTR lpszDll, WCHAR* lpszProcess)
{
	DWORD  dwSize, dwWritten, dwRet;
	WCHAR   FilePath[MAX_PATH] = {};
	//获取DLL的路径;
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
	//打开进程，获得该进程句柄;
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
		, FALSE, dwRet);
	if (NULL == hProcess)
	{
		return false;
	}
	//在进程中申请一快内存;
	LPVOID lpBuf = (LPVOID)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (lpBuf == NULL)
	{
		CloseHandle(hProcess);
		return false;
	}
	//把DLL写入申请到的内存;
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
	//获得LoadLibraryW函数的地址;
	LPVOID pFunc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	//创建远程线程;
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

/*-----------------------进程操作相关函数;------------------------*/
/******************************************************
功能描述：查找指定的进程调用的动态连接库;
参数说明：1.exeName：要查找的进程名;
返回值：如果成功返回链表的头head，失败返回NULL;
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
功能描述：查找指定的动态连接库被那些进程调用;
参数说明：1.dllName：要查找的动态连接库;
返回值：如果成功返回链表的头head，失败返回NULL;
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
功能描述：创造所有进程的快照;
返回值：如果成功返回链表的头head，失败返回NULL;
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
功能描述：根据进程ID结束进程;
参数说明：1.dwId：进程ID;
返回值：如果成功返回TRUE，失败返回FALSE;
******************************************************/
BOOL TerminateProcessFromId(DWORD dwId)
{
	BOOL bRet = FALSE;
	// 打开目标进程,取得进程句柄;
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwId);
	if (hProcess != NULL)
	{
		bRet = ::TerminateProcess(hProcess, 0);
	}
	CloseHandle(hProcess);
	return bRet;
}
/*------------------------------------------------------------*/

//自删除;
void SelfDelete()
{
	TCHAR szModule[MAX_PATH],
		szComspec[MAX_PATH],
		szParams[MAX_PATH];

	//获取文件的路径和环境变量"COMSPEC"的值即mcd路径;
	if ((GetModuleFileName(0, szModule, MAX_PATH) != 0) &&
		(GetShortPathName(szModule, szModule, MAX_PATH) != 0) &&
		(GetEnvironmentVariable(L"COMSPEC", szComspec, MAX_PATH) != 0))
	{
		//设置命令行参数;
		lstrcpy(szParams, L" /c del ");
		lstrcat(szParams, szModule);
		lstrcat(szParams, L" > nul");
		lstrcat(szComspec, szParams);

		std::cout << szComspec << std::endl;
		//设置数据结构数据;
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