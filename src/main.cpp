//Codeant - DaMaYi 15:05 星期二 2024年5月11日
//https://github.com/Codeant-GitHub

#pragma once
#define _WIN32_WINNT 0x0601

#include <windows.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <iomanip>
#include <ctime>

#include <stdio.h>
#include <Psapi.h>
#include <stdint.h>
#include <tlhelp32.h>

#include <tchar.h>

#include <format>
#include <nlohmann/json.hpp>

#include <comdef.h>
#include <curl/curl.h>

#include "VMProtectSDK.h"

size_t req_reply(void* ptr, size_t size, size_t nmemb, void* stream) {
	if (stream == NULL || ptr == NULL || size == 0)
		return 0;

	size_t realsize = size * nmemb;
	std::string* buffer = (std::string*)stream;
	if (buffer != NULL) {
		buffer->append((const char*)ptr, realsize);
	}
	return realsize;
}

static CURLcode http_get(const std::string& url, bool post, const std::string& req, std::string& response, std::shared_ptr<std::list<std::string>> header = nullptr, int connect_timeout = 10, int timeout = 10)
{
	CURL* curl = curl_easy_init();
	CURLcode res;
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_POST, post);
		if (!req.empty()) {
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.c_str());
		}
		struct curl_slist* headers = NULL;
		if (header && header->size() > 0) {
			std::list<std::string>::iterator iter, iterEnd;
			iter = header->begin();
			iterEnd = header->end();
			for (; iter != iterEnd; iter++) {
				headers = curl_slist_append(headers, iter->c_str());
			}

			if (headers != NULL) {
				curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
			}
		}
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, true);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, NULL);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_reply);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
		res = curl_easy_perform(curl);
		if (headers != NULL) {
			curl_slist_free_all(headers);
		}
	}
	curl_easy_cleanup(curl);
	return res;
}

std::string get_online_vip(std::string user)
{
	std::string url = VMProtectDecryptStringA("https://www.rdrtools.com/Hong_Kong.json");
	std::string response;
	std::string vip;
	if (http_get(url, false, "", response) == CURLE_OK) {
		try {
			nlohmann::json root = nlohmann::json::parse(response);
			vip = root[user].get<std::string>();
		}
		catch (nlohmann::json::parse_error& e) {
			std::cout << "\n登陆失败，卡密错误....\n";
		}
	}

	return vip;
}

uint64_t get_local_time()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch())
		.count();
}

__int64 timestamp_milliseconds(uint64_t timestamp)
{
	// 将时间戳转换为std::chrono::milliseconds类型
	std::chrono::milliseconds ms(timestamp);

	// 将std::chrono::milliseconds转换为std::chrono::system_clock的时间点
	std::chrono::system_clock::time_point tp(ms);

	// 将std::chrono::system_clock::time_point转换为std::time_t类型
	std::time_t t = std::chrono::system_clock::to_time_t(tp);

	// 使用std::localtime将std::time_t类型转换为struct std::tm类型
	struct tm* stime = localtime(&t);
	char tmp[32] = { NULL };
	sprintf(tmp, "%04d%02d%02d%02d", 1900 + stime->tm_year, 1 + stime->tm_mon, stime->tm_mday, stime->tm_hour);

	// 打印格式化后的时间字符串
	//std::cout << "Formatted time: " << buffer << std::endl;

	return atoi(tmp);
}

HMODULE GetProcessModuleHandleByName(DWORD pid, LPCSTR ModuleName)
{
	MODULEENTRY32 ModuleInfo;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!hSnapshot)
	{
		return 0;
	}
	ZeroMemory(&ModuleInfo, sizeof(MODULEENTRY32));
	ModuleInfo.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hSnapshot, &ModuleInfo))
	{
		return 0;
	}
	do
	{
		if (!lstrcmpi(ModuleInfo.szModule, ModuleName))
		{
			CloseHandle(hSnapshot);
			return ModuleInfo.hModule;
		}
	} while (Module32Next(hSnapshot, &ModuleInfo));
	CloseHandle(hSnapshot);
	return 0;
}

DWORD GetProcessIDByName(const char* pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (strcmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

BOOL bInjectLibrary(HANDLE hProcess, const char* szDllToInjectPath)
{
	LPVOID lpRemoteAddress = VirtualAllocEx(hProcess, NULL, strlen(szDllToInjectPath), MEM_COMMIT, PAGE_READWRITE);

	if (!lpRemoteAddress)
		return FALSE;

	if (!WriteProcessMemory(hProcess, lpRemoteAddress, (LPVOID)szDllToInjectPath, strlen(szDllToInjectPath), NULL))
		return FALSE;

	HANDLE hThread = NULL;

	if (!(hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA"), lpRemoteAddress, NULL, NULL)))
		return FALSE;

	CloseHandle(hThread);
	return TRUE;
}

//获取当前路径
std::string 获取当前路径()
{
	TCHAR szFilePath[MAX_PATH + 1] = { 0 };
	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	(_tcsrchr(szFilePath, _T('\\')))[1] = 0; // 删除文件名，只获得路径字串
	std::string str_url = szFilePath;  // 例如str_url==e:\program\Debug\

	return str_url;
}

static char 请填写账号[256] = "";

void 读取账号()
{
	std::ostringstream ss;
	ss << 获取当前路径() << VMProtectDecryptStringA("\\") << "config.txt";
	GetPrivateProfileString("root", "pas", "", 请填写账号, 256, ss.str().c_str());
}

void 保存账号()
{
	std::ostringstream ss;
	ss << 获取当前路径() << VMProtectDecryptStringA("\\") << "config.txt";
	WritePrivateProfileString("root", "pas", 请填写账号, ss.str().c_str());
}

int main()
{
	VMProtectBeginUltra("main");

    // 获取控制台句柄
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // 设置文本颜色为绿色
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

    std::cout << R"kek(     _______________ _____
    |_  |  ___| ___ \  __ \
      | | |_  | |_/ / |  \/
      | |  _| | ___ \ | __
  /\__/ / |   | |_/ / |_\ \
  \____/\_|   \____/ \____/

)kek";

    std::cout << "\n 软件名：疾风表哥";

    std::cout << "\n 版本号：2.9.4";

    std::cout << "\n*************************************";

    std::cout << "\n 公告： 11";

    std::cout << "\n*************************************";

    std::cout << "\n有问题先去看使用说明。使用说明能解决90%的使用问题。\n";

	读取账号();

	if (timestamp_milliseconds(get_local_time()) > 2024063013)
	{
		std::cout << "\n运行失败，发生了错误....\n";

		std::cout << "\n\n " << system("pause");
	}
	else
	{
		//std::cout << "\n" << get_online_vip() << "\n";

		//HOIQJCZNTPKNVSCWGJFGYZFCJ

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);

		std::cout << "\n请在下方输入卡号，输入完毕后按回车确认：\n";

		std::cin >> 请填写账号;

		if (get_online_vip(请填写账号) == VMProtectDecryptStringA("1"))
		{
			std::ostringstream cc;
			cc << 获取当前路径() << VMProtectDecryptStringA("\\") << "config.txt";
			WritePrivateProfileString("root", "pas", 请填写账号, cc.str().c_str());


			DWORD PidRDR = NULL;

			if (GetProcessIDByName("RDR2.exe"))
			{
				PidRDR = GetProcessIDByName("RDR2.exe");
			}
			else if (GetProcessIDByName("rdr2.exe"))
			{
				PidRDR = GetProcessIDByName("rdr2.exe");
			}

			if (PidRDR)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PidRDR);

				std::ostringstream ss;
				ss << 获取当前路径() << "\\JiFeng.dll";

				if (!bInjectLibrary(hProcess, ss.str().c_str()))

					CloseHandle(hProcess);

				std::cout << "\n正在登陆，请稍后...\n";

				std::cout << "\n登陆成功,到期时间为：2122-12-03 10:15:37\n";
			}
			else
			{
				std::cout << "\n登陆失败，未检测到游戏....\n";
			}
		}
		else
		{
			std::cout << "\n登陆失败，卡密错误....\n";
		}
	}
    std::cout << "\n\n " << system("pause");

	VMProtectEnd();

	return false;
}