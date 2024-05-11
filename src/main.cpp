//Codeant - DaMaYi 15:05 ���ڶ� 2024��5��11��
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
			std::cout << "\n��½ʧ�ܣ����ܴ���....\n";
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
	// ��ʱ���ת��Ϊstd::chrono::milliseconds����
	std::chrono::milliseconds ms(timestamp);

	// ��std::chrono::millisecondsת��Ϊstd::chrono::system_clock��ʱ���
	std::chrono::system_clock::time_point tp(ms);

	// ��std::chrono::system_clock::time_pointת��Ϊstd::time_t����
	std::time_t t = std::chrono::system_clock::to_time_t(tp);

	// ʹ��std::localtime��std::time_t����ת��Ϊstruct std::tm����
	struct tm* stime = localtime(&t);
	char tmp[32] = { NULL };
	sprintf(tmp, "%04d%02d%02d%02d", 1900 + stime->tm_year, 1 + stime->tm_mon, stime->tm_mday, stime->tm_hour);

	// ��ӡ��ʽ�����ʱ���ַ���
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

//��ȡ��ǰ·��
std::string ��ȡ��ǰ·��()
{
	TCHAR szFilePath[MAX_PATH + 1] = { 0 };
	GetModuleFileName(NULL, szFilePath, MAX_PATH);
	(_tcsrchr(szFilePath, _T('\\')))[1] = 0; // ɾ���ļ�����ֻ���·���ִ�
	std::string str_url = szFilePath;  // ����str_url==e:\program\Debug\

	return str_url;
}

static char ����д�˺�[256] = "";

void ��ȡ�˺�()
{
	std::ostringstream ss;
	ss << ��ȡ��ǰ·��() << VMProtectDecryptStringA("\\") << "config.txt";
	GetPrivateProfileString("root", "pas", "", ����д�˺�, 256, ss.str().c_str());
}

void �����˺�()
{
	std::ostringstream ss;
	ss << ��ȡ��ǰ·��() << VMProtectDecryptStringA("\\") << "config.txt";
	WritePrivateProfileString("root", "pas", ����д�˺�, ss.str().c_str());
}

int main()
{
	VMProtectBeginUltra("main");

    // ��ȡ����̨���
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // �����ı���ɫΪ��ɫ
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

    std::cout << R"kek(     _______________ _____
    |_  |  ___| ___ \  __ \
      | | |_  | |_/ / |  \/
      | |  _| | ___ \ | __
  /\__/ / |   | |_/ / |_\ \
  \____/\_|   \____/ \____/

)kek";

    std::cout << "\n �������������";

    std::cout << "\n �汾�ţ�2.9.4";

    std::cout << "\n*************************************";

    std::cout << "\n ���棺 11";

    std::cout << "\n*************************************";

    std::cout << "\n��������ȥ��ʹ��˵����ʹ��˵���ܽ��90%��ʹ�����⡣\n";

	��ȡ�˺�();

	if (timestamp_milliseconds(get_local_time()) > 2024063013)
	{
		std::cout << "\n����ʧ�ܣ������˴���....\n";

		std::cout << "\n\n " << system("pause");
	}
	else
	{
		//std::cout << "\n" << get_online_vip() << "\n";

		//HOIQJCZNTPKNVSCWGJFGYZFCJ

		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);

		std::cout << "\n�����·����뿨�ţ�������Ϻ󰴻س�ȷ�ϣ�\n";

		std::cin >> ����д�˺�;

		if (get_online_vip(����д�˺�) == VMProtectDecryptStringA("1"))
		{
			std::ostringstream cc;
			cc << ��ȡ��ǰ·��() << VMProtectDecryptStringA("\\") << "config.txt";
			WritePrivateProfileString("root", "pas", ����д�˺�, cc.str().c_str());


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
				ss << ��ȡ��ǰ·��() << "\\JiFeng.dll";

				if (!bInjectLibrary(hProcess, ss.str().c_str()))

					CloseHandle(hProcess);

				std::cout << "\n���ڵ�½�����Ժ�...\n";

				std::cout << "\n��½�ɹ�,����ʱ��Ϊ��2122-12-03 10:15:37\n";
			}
			else
			{
				std::cout << "\n��½ʧ�ܣ�δ��⵽��Ϸ....\n";
			}
		}
		else
		{
			std::cout << "\n��½ʧ�ܣ����ܴ���....\n";
		}
	}
    std::cout << "\n\n " << system("pause");

	VMProtectEnd();

	return false;
}