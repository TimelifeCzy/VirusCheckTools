// TestModule.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
/********************************************************************
 wanncry virus clear tools 
********************************************************************/

#define _WIN32_DCOM

#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <psapi.h>
#include <atlstr.h>
#include <shlobj_core.h>
#include <vector>

using namespace std;

typedef struct _WANNCRYINFO
{
	DWORD CurrentProcessPid;
	DWORD ParentProcessPid;
	WCHAR WanncryProcesName[MAX_PATH];
}WANNCRYINFO, *PWANNCRYINFO;


// 保存病毒路径
TCHAR		pszFullPath[MAX_PATH];

// 是否有病毒标志
DWORD		Wanncryflag = 0;

// 保存当前进程PID查找
vector<WANNCRYINFO> g_wanncry;

// 保存父进程PID查找
vector<WANNCRYINFO> g_parwanncry;

// 创建一个vector or Array保存全部的wanncry的释放子进程名称
WCHAR WanncryHomeName[][20] = { L"mssecsvc.exe", L"mssecsvr.exe",L"tasksche.exe" ,L"@WanaDecryptor@.exe", L"taskhsvc.exe" };

FILE* g_pFile = NULL;

char* UnicodeToAnsi(const wchar_t* szStr)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
	{
		return NULL;
	}
	char* pResult = new char[nLen];
	WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
	return pResult;
}

int InitLog()
{
	wstring tempath;
	WCHAR* path = 0;
	char DesktopPath[MAX_PATH] = { 0, };
	HRESULT result = SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &path);
	if (result == S_OK)
	{
		wprintf(L"%s\n", path);
	}
	else
		return -1;

	// DesktopPathLogCat
	tempath = path;
	tempath += L"\\";
	tempath += L"WanncryCheck.txt";
	CoTaskMemFree(path);

	// wchar --> char
	strcpy(DesktopPath, UnicodeToAnsi(tempath.c_str()));

	g_pFile = fopen(DesktopPath, "wt+");
	if (!g_pFile)
		return -1;

	return 0;
}

//获取进程完整路径
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = '\0';
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径

				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}
BOOL GetProcessFullPath(DWORD dwPID)
{
	TCHAR		szImagePath[MAX_PATH];
	HANDLE		hProcess;
	if (!pszFullPath)
		return FALSE;

	pszFullPath[0] = '\0';
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
	if (!hProcess)
		return FALSE;

	if (!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!DosPathToNtPath(szImagePath, pszFullPath))
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);
	return TRUE;
}
BOOL GetProcessPath(DWORD pid)
{
	HANDLE hSnapshot = NULL;
	BOOL fOk;
	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return NULL;
	}
	for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe))
	{
		if (pid == pe.th32ProcessID)
		{
			GetProcessFullPath(pe.th32ProcessID);
			break;
		}
		//ShowModule(pe.th32ProcessID,pe.szExeFile); //仅32位
	}
	return 0;
}

/*
	Wanncry子进程查杀:
		参数 flag 子进程检测：0  父进程检测：1
*/
BOOL GetVirusProcess(DWORD flag)
{
	WANNCRYINFO wanncryinfo = { 0, };
	// 初始化无效的句柄值
	HANDLE hprocess = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W p_32 = { 0 };
	// 索引
	int index = 0;
	// 重复判定
	int flagbit = 0;
	// 1.创建进程快照
	hprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE != hprocess)
	{
		p_32.dwSize = sizeof(PROCESSENTRY32W);
		// 开始遍历进程
		if (!Process32First(hprocess, &p_32))
		{
			CloseHandle(hprocess);
			return FALSE;
		}
		if (flag == 0)
		{
			do
			{
				for (size_t i = 0; i < sizeof(WanncryHomeName); ++i)
				{
					if (WanncryHomeName[i][0] == NULL)
						break;

					// find of wanncry virus
					if (!lstrcmpW(p_32.szExeFile, &WanncryHomeName[i][0]))
					{
						wanncryinfo.CurrentProcessPid = p_32.th32ProcessID;
						wanncryinfo.ParentProcessPid = p_32.th32ParentProcessID;
						StrCpyW(wanncryinfo.WanncryProcesName, p_32.szExeFile);
						g_wanncry.push_back(wanncryinfo);
						Wanncryflag++;
					}
				}
			} while (Process32Next(hprocess, &p_32));
		}
		else if (flag == 1)
		{
			do
			{
				for (int i = 0; i < g_wanncry.size(); ++i)
				{
					if (p_32.th32ProcessID == g_wanncry[i].ParentProcessPid)
					{
						// 重复的父进程不添加不添加
						for (int k = 0; k < g_parwanncry.size(); ++k)
						{
							if (g_parwanncry[k].ParentProcessPid == p_32.th32ProcessID)
							{
								flagbit = 1;
								break;
							}
						}

						if (!flagbit)
						{
							wanncryinfo.CurrentProcessPid = p_32.th32ProcessID;
							wanncryinfo.ParentProcessPid = p_32.th32ParentProcessID;
							StrCpyW(wanncryinfo.WanncryProcesName, p_32.szExeFile);
							g_parwanncry.push_back(wanncryinfo);
							Wanncryflag++;
							flagbit = 0;
						}

					}
				}
			} while (Process32Next(hprocess, &p_32));
		}
	}
	CloseHandle(hprocess);
	hprocess = NULL;
}

// 获取Wanncry进程
void GetWanncryScan()
{
	// 保存被结束进程的pid
	HANDLE hpminate = NULL;
	// 查杀标准的子进程
	GetVirusProcess(0);
	GetVirusProcess(1);

	for (int i = 0; i < g_parwanncry.size(); ++i)
	{

		// Get file path pszFullPath
		GetProcessPath(g_parwanncry[i].CurrentProcessPid);

		if (pszFullPath == NULL)
		{
			wprintf(L"%s进程路径获取失败，请手动排查\n", g_wanncry[i].WanncryProcesName);
			StrCpyW(pszFullPath, L"无法获取路径");
		}

		if (!lstrcmp(L"explorer.exe", g_parwanncry[i].WanncryProcesName))
			continue;

		wprintf(L"发现Wanncry进程: 父进程PID: %d\t子进程pid：%d\n进程名：%s\t路径：%s\n",
			g_parwanncry[i].ParentProcessPid,
			g_parwanncry[i].CurrentProcessPid,
			g_parwanncry[i].WanncryProcesName,
			pszFullPath);

		fwprintf(g_pFile, L"发现Wanncry进程: 父进程PID: %d\t子进程pid：%d\n进程名：%s\t,路径：%s\n",
			g_parwanncry[i].ParentProcessPid,
			g_parwanncry[i].CurrentProcessPid,
			g_parwanncry[i].WanncryProcesName,
			pszFullPath);

		// terprocess
		hpminate = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_parwanncry[i].CurrentProcessPid);
		TerminateProcess(hpminate, 0);
		wprintf(L"%s\t已结束\n", g_parwanncry[i].WanncryProcesName);
		fwprintf(g_pFile, L"%s\t已结束\n", g_parwanncry[i].WanncryProcesName);

		CString pathcat;
		// local file move  
		pathcat = pszFullPath;
		pathcat = pathcat + ".virus";
		MoveFile(pszFullPath, pathcat.GetBuffer());

		wprintf(L"防止病毒被再次执行已重名命，请手动拷贝病毒或删除：%s\n", pathcat.GetBuffer());
		fwprintf(g_pFile, L"防止病毒被再次执行已重名命，请手动拷贝病毒或删除：%s\n", pathcat.GetBuffer());

		fflush(g_pFile);
	}

	for (int i = 0; i < g_wanncry.size(); ++i)
	{
		// Get file path pszFullPath
		GetProcessPath(g_wanncry[i].CurrentProcessPid);

		if (pszFullPath == NULL)
		{
			wprintf(L"%s进程路径获取失败，请手动排查\n", g_wanncry[i].WanncryProcesName);
			StrCpyW(pszFullPath, L"无法获取路径");
		}

		wprintf(L"发现Wanncry进程: 父进程PID: %d\t子进程pid：%d\n进程名：%s\t,路径：%s\n",
			g_wanncry[i].ParentProcessPid,
			g_wanncry[i].CurrentProcessPid,
			g_wanncry[i].WanncryProcesName,
			pszFullPath);

		fwprintf(g_pFile, L"发现Wanncry进程: 父进程PID: %d\t子进程pid：%d\n进程名：%s\t路径：%s\n",
			g_wanncry[i].ParentProcessPid,
			g_wanncry[i].CurrentProcessPid,
			g_wanncry[i].WanncryProcesName,
			pszFullPath);


		// terprocess
		hpminate = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_wanncry[i].CurrentProcessPid);
		TerminateProcess(hpminate, 0);
		wprintf(L"%s\t已结束\n", g_wanncry[i].WanncryProcesName);
		fwprintf(g_pFile, L"%s\t已结束\n", g_wanncry[i].WanncryProcesName);

		CString pathcat;
		// local file move  
		pathcat = pszFullPath;
		pathcat = pathcat + ".virus";
		MoveFile(pszFullPath, pathcat.GetBuffer());

		wprintf(L"防止病毒被再次执行已重名命，请手动拷贝病毒或删除：%s\n", pathcat.GetBuffer());
		fwprintf(g_pFile, L"防止病毒被再次执行已重名命，请手动拷贝病毒或删除：%s\n", pathcat.GetBuffer());

		fflush(g_pFile);
	}



	printf("\n病毒总数：%d个\n", Wanncryflag);
	if (Wanncryflag)
		printf("请拷贝与删除病毒\n");
	else
		printf("没有检测到Wanncry\n");
}

int __cdecl wmain()
{
	setlocale(LC_ALL, "chs");
	InitLog();
	printf("Wanncry启动工作，正在进程扫描......\n");
	fwprintf(g_pFile, L"%s", L"Wanncry启动工作，正在进程扫描......\n");
	fflush(g_pFile);
	GetWanncryScan();
	fclose(g_pFile);
	system("pause");
	return 0;
}