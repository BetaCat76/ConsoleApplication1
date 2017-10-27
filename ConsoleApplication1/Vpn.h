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
	static void connectvpn();
public:
	Vpn();
	~Vpn();

};

