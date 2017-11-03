#pragma once

#include <Windows.h>
#include <Ras.h>
#pragma comment(lib, "rasapi32.lib")

enum vpn_type
{
	pptp,
	l2tp_psk,
	l2tp_cert,
	ikev2_eap,
	ikev2_cert,
};

class Vpn
{
public:
	static void createvpn(const wchar_t *name, const wchar_t *server, const wchar_t *username, const wchar_t *password,
		const wchar_t *psk, int type);
	static HRASCONN connectvpn(const wchar_t * entryname, const wchar_t *username, const wchar_t *password);
	static void WINAPI RasDialFunc(UINT unMsg, RASCONNSTATE rasconnstate, DWORD dwError);
	static bool disconnect(const wchar_t * entryname);
	static bool getEntryConnection(const wchar_t * entryname, RASCONN & conn);
	static bool deleteEntry(const wchar_t * entryname);
public:
	Vpn();
	~Vpn();

};

