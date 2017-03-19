#include "MyDll.h"
#include <stdio.h>
#include <string>
#include <map>
#include <comutil.h>
#pragma comment(lib, "comsuppw.lib")

#if _DEBUG
#include <crtdbg.h>
#endif

void printfmodule(pModule pMod)
{
	pModule pTemp = pMod;
	while (pTemp)
	{
		char* pdata = _com_util::ConvertBSTRToString(pTemp->szExePath);
		std::cout << pTemp->th32ProcessID << "\t" << pdata << std::endl;
		pTemp = pTemp->next;
		delete pdata;
	}
}

void test_findexedll(const char* pExeName)
{
	std::cout << "----------test_findexedll begin-------------" << std::endl;
	BSTR exeName = _com_util::ConvertStringToBSTR(pExeName);
	pModule pMod = FindExeDll(exeName);
	printfmodule(pMod);
	SysFreeString(exeName);
	delete pMod;
	std::cout << "----------test_findexedll end-------------" << std::endl;
}

void test_closeprocess(pModule pMod)
{
	std::cout << "----------test_closeprocess begin-------------" << std::endl;
	pModule pTemp = pMod;
	while (pTemp)
	{
		char* pdata = "进程关闭失败!";
		if (TerminateProcessFromId(pTemp->th32ProcessID))
		{
			pdata = "进程关闭成功!";
		}
		std::cout << pTemp->th32ProcessID << "\t" << pdata << std::endl;
		pTemp = pTemp->next;
	}
	std::cout << "----------test_closeprocess end-------------" << std::endl;
}

void test_finddllexe(const char* pDllName, int nClose)
{
	std::cout << "----------test_finddllexe begin-------------" << std::endl;
	BSTR dllName = _com_util::ConvertStringToBSTR(pDllName);
	pModule pMod = FindDllExe(dllName);
	printfmodule(pMod);
	if (1 == nClose){
		test_closeprocess(pMod);
	}
	SysFreeString(dllName);
	delete pMod;
	std::cout << "----------test_finddllexe end-------------" << std::endl;
}

void test_snapshot()
{
	pModule pMod = SnapshotProcess();
	printfmodule(pMod);
	delete pMod;
}

int main(int argc, char *argv[])
{
	bool bHelp = true;
#if _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
	//_CrtSetBreakAlloc(153);
	for (int i = 0; i < argc; ++i)
	{
		std::cout << argv[i] << std::endl;
	}
#endif
	if (2 <= argc)
	{
		int index = 1;
		_strupr_s(argv[index], strlen(argv[index]) + 1);
		if (0 == strcmp("/SNAPSHOT", argv[index]))
		{
			test_snapshot();
			bHelp = false;
		}
		else if (0 == strcmp("/SELFDELETE", argv[index]))
		{
			SelfDelete();
			bHelp = false;
		}
		else if (0 == strcmp("/SHUTDOWN", argv[index]))
		{
			CloseComputer();
			bHelp = false;
		}
		else if (0 == strcmp("/RESTART", argv[index]))
		{
			ReComputer();
			bHelp = false;
		}

		if (3 <= argc)
		{
			if (0 == strcmp("/FINDEXEDLL", argv[index]))
			{
				test_findexedll(argv[index + 1]);
				bHelp = false;
			}
			else if (0 == strcmp("/FINDDLLEXE", argv[index]))
			{
				int n = 0;
				if (4 <= argc)
				{
					n = atoi(argv[index + 2]);
				}
				test_finddllexe(argv[index + 1], n);
				bHelp = false;
			}
		}
	}
	
	if (bHelp)
	{
		std::cout << "关机: /Shutdown;" << std::endl;
		std::cout << "重启: /Restart;" << std::endl;
		std::cout << "进程快照: /Snapshot;" << std::endl;
		std::cout << "自删除: /SelfDelete;" << std::endl;
		std::cout << "查找指定的进程调用的动态连接库: /FindExeDll exe名称;" << std::endl;
		std::cout << "查找指定的动态连接库被那些进程调用: /FindDllExe dll名称;" << std::endl;
	}
#if _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
	return 0;
}