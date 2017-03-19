//源码地址:http://blog.csdn.net/jinhill/article/details/4842819

#ifndef _MYDLLMYDLL
#define _MYDLLMYDLL
#include <windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

typedef struct Module{
	Module()
	{
		th32ProcessID = 0;
		memset(szExePath, 0, sizeof(szExePath));
		next = NULL;
	}
	~Module()
	{
		if (next)
		{
			delete next;
			next = NULL;
		}
	}
	DWORD th32ProcessID;
	WCHAR szExePath[MAX_PATH];
	struct Module *next;
}ModuleInfo, *pModule;

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@函数@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;
int CloseComputer();									//关机;
int ReComputer();										//重启;
bool WINAPI EnablePrivilege(LPCTSTR PrivilegeName);		//调整进程级别;
bool InsertDll(LPCTSTR lpszDll, WCHAR* lpszProcess);	//使用远程线程插入dll;
DWORD FindProcessId(WCHAR* lpszProcess);				//查找进程PID;
pModule FindExeDll(WCHAR* exeName);						//查找指定的进程调用的动态连接库;
pModule FindDllExe(WCHAR* dllName);						//查找指定的动态连接库被那些进程调用;
pModule SnapshotProcess();								//进程快照;
void SelfDelete();										//自删除函数;
BOOL TerminateProcessFromId(DWORD dwId);				//根据进程ID结束进程;

#endif