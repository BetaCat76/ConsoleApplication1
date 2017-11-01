#include "stdafx.h"
#include "Vpn.h"

void Vpn::createvpn(const wchar_t *name, const wchar_t *server, const wchar_t *username, const wchar_t *password,
	const wchar_t *psk, int type)
{
	DWORD size = 0;
	RasGetEntryProperties(NULL, L"", NULL, &size, NULL, NULL);
	LPRASENTRY pras = (LPRASENTRY)malloc(size);
	memset(pras, 0, size);
	pras->dwSize = size; // 对象大小
	pras->dwfOptions = RASEO_RemoteDefaultGateway; //选项
	pras->dwType = RASET_Vpn; // 类型是vpn
	pras->dwRedialCount = 0; // 重拨次数
	pras->dwRedialPause = 60; // 重拨间隔
	pras->dwfNetProtocols = RASNP_Ip;
	pras->dwEncryptionType = ET_Optional;
	wcscpy_s(pras->szLocalPhoneNumber, server); // IP地址
	wcscpy_s(pras->szDeviceType, RASDT_Vpn); // 设备类型vpn

	if (pptp == type)
	{
		pras->dwfOptions |= RASEO_RequireEncryptedPw;
		pras->dwVpnStrategy = VS_PptpOnly;
	}
	else if (l2tp_psk == type)
	{
		pras->dwVpnStrategy = VS_L2tpOnly;
		pras->dwfOptions |= RASEO_RequireEncryptedPw;
		pras->dwfOptions2 |= RASEO2_UsePreSharedKey;
	}
	else if (l2tp_cert == type)
	{
		pras->dwVpnStrategy = (VS_L2tpOnly);
		pras->dwfOptions2 |= RASEO2_DisableIKENameEkuCheck;
	}
	else if (ikev2_eap == type)
	{
		pras->dwfOptions |= (RASEO_RequireDataEncryption | RASEO_RequireEAP | RASEO_RequireMsCHAP2);
		pras->dwVpnStrategy = VS_Ikev2Only;
	}
	else if (ikev2_cert == type)
	{
		pras->dwfOptions |= RASEO_RequireDataEncryption;
		pras->dwfOptions2 |= RASEO2_RequireMachineCertificates;
		pras->dwVpnStrategy = VS_Ikev2Only;
	}

	RasSetEntryProperties(NULL, name, pras, pras->dwSize, NULL, 0);
	if (l2tp_psk == type)
	{
		RASCREDENTIALS ras_cre_psk = { 0 };
		ras_cre_psk.dwSize = sizeof(ras_cre_psk);
		ras_cre_psk.dwMask = RASCM_PreSharedKey;
		wcscpy_s(ras_cre_psk.szPassword, psk);
		RasSetCredentials(NULL, name, &ras_cre_psk, FALSE);
	}

	RASCREDENTIALS ras_cre = { 0 };
	ras_cre.dwSize = sizeof(ras_cre);
	ras_cre.dwMask = RASCM_UserName | RASCM_Password;
	wcscpy_s(ras_cre.szUserName, username);
	wcscpy_s(ras_cre.szPassword, password);
	RasSetCredentials(NULL, name, &ras_cre, FALSE);


	free(pras);
}

void Vpn::connectvpn(const wchar_t *username, const wchar_t *password)
{
	DWORD size = sizeof(RASDIALPARAMS);
	LPRASDIALPARAMS pras= (LPRASDIALPARAMS)malloc(size);
	memset(pras, 0, size);
	pras->dwSize = size;
	wcscpy_s(pras->szEntryName, L"");
}

Vpn::Vpn()
{
}


Vpn::~Vpn()
{
}
