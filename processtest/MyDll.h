//Դ���ַ:http://blog.csdn.net/jinhill/article/details/4842819

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

//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@����@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@;
int CloseComputer();									//�ػ�;
int ReComputer();										//����;
bool WINAPI EnablePrivilege(LPCTSTR PrivilegeName);		//�������̼���;
bool InsertDll(LPCTSTR lpszDll, WCHAR* lpszProcess);	//ʹ��Զ���̲߳���dll;
DWORD FindProcessId(WCHAR* lpszProcess);				//���ҽ���PID;
pModule FindExeDll(WCHAR* exeName);						//����ָ���Ľ��̵��õĶ�̬���ӿ�;
pModule FindDllExe(WCHAR* dllName);						//����ָ���Ķ�̬���ӿⱻ��Щ���̵���;
pModule SnapshotProcess();								//���̿���;
void SelfDelete();										//��ɾ������;
BOOL TerminateProcessFromId(DWORD dwId);				//���ݽ���ID��������;

#endif