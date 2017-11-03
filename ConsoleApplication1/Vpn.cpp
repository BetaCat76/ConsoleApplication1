#include "stdafx.h"
#include "Vpn.h"
#include <iostream>

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

HRASCONN Vpn::connectvpn(const wchar_t * entryname, const wchar_t *username, const wchar_t *password)
{
	RASDIALPARAMS pras;
	ZeroMemory(&pras, sizeof(RASDIALPARAMS));
	pras.dwSize = sizeof(RASDIALPARAMS);
	lstrcpy(pras.szEntryName, entryname);
	lstrcpy(pras.szUserName, username);
	lstrcpy(pras.szPassword, password);

	DWORD ret;
	HRASCONN conn=NULL;
	ret = RasDial(NULL, NULL, &pras, 0, &Vpn::RasDialFunc, &conn);
	if (ret != 0) {
		std::cout << ret;
		std::cout << std::endl;
	}
	return conn;
}

void WINAPI Vpn::RasDialFunc(UINT unMsg, RASCONNSTATE rasconnstate, DWORD dwError)
{
	wchar_t szRasString[256] = { 0 }; // Buffer for storing the error string
	wchar_t szTempBuf[256] = { 0 };  // Buffer used for printing out the text
	if (dwError)  // Error occurred
	{
		RasGetErrorString(static_cast<UINT>(dwError), reinterpret_cast<LPWSTR>(szRasString), 256);
		ZeroMemory(static_cast<LPVOID>(szTempBuf), sizeof(szTempBuf));
		std::cout << szRasString;
		return;
	}

	// Map each of the states of RasDial() and display on the screen
	// the next state that RasDial() is entering
	switch (rasconnstate)
	{
	case RASCS_OpenPort:
		std::cout << "RASCS_OpenPort = " << rasconnstate;
		std::cout << "Opening port...";
		std::cout << std::endl;
		//g_pFrame->setUserInfo("test","test","test","test","test");
		break;
	case RASCS_PortOpened:
		std::cout << "RASCS_PortOpened = " << rasconnstate;
		std::cout << "Port opened.";
		std::cout << std::endl;
		break;
	case RASCS_ConnectDevice:
		std::cout << "RASCS_ConnectDevice = " << rasconnstate;
		std::cout << "Connecting device...";
		std::cout << std::endl;
		break;
	case RASCS_DeviceConnected:
		std::cout << "RASCS_DeviceConnected = " << rasconnstate;
		std::cout << "Device connected.";
		std::cout << std::endl;
		break;
	case RASCS_AllDevicesConnected:
		std::cout << "RASCS_AllDevicesConnected = " << rasconnstate;
		std::cout << "All devices connected.";
		std::cout << std::endl;
		break;
	case RASCS_Authenticate:
		std::cout << "RASCS_Authenticate = " << rasconnstate;
		std::cout << "Authenticating...";
		std::cout << std::endl;
		break;
	case RASCS_AuthNotify:
		std::cout << "RASCS_AuthNotify = " << rasconnstate;
		std::cout << "Authentication notify.";
		std::cout << std::endl;
		break;
	case RASCS_AuthRetry:
		std::cout << "RASCS_AuthRetry = \n" << rasconnstate;
		std::cout << "Retrying authentication...";
		std::cout << std::endl;
		break;
	case RASCS_AuthCallback:
		std::cout << "RASCS_AuthCallback = " << rasconnstate;
		std::cout << "Authentication callback...";
		std::cout << std::endl;
		break;
	case RASCS_AuthChangePassword:
		std::cout << "RASCS_AuthChangePassword = " << rasconnstate;
		std::cout << "Change password...";
		std::cout << std::endl;
		break;
	case RASCS_AuthProject:
		std::cout << "RASCS_AuthProject = " << rasconnstate;
		std::cout << "Projection phase started...";
		std::cout << std::endl;
		break;
	case RASCS_AuthLinkSpeed:
		std::cout << "RASCS_AuthLinkSpeed = " << rasconnstate;
		std::cout << "Negoting speed...";
		std::cout << std::endl;
		break;
	case RASCS_AuthAck:
		std::cout << "RASCS_AuthAck = " << rasconnstate;
		std::cout << "Authentication acknowledge...";
		std::cout << std::endl;
		break;
	case RASCS_ReAuthenticate:
		std::cout << "RASCS_ReAuthenticate = " << rasconnstate;
		std::cout << "Retrying Authentication...";
		std::cout << std::endl;
		break;
	case RASCS_Authenticated:
		std::cout << "RASCS_Authenticated = " << rasconnstate;
		std::cout << "Authentication complete.";
		std::cout << std::endl;
		break;
	case RASCS_PrepareForCallback:
		std::cout << "RASCS_PrepareForCallback = " << rasconnstate;
		std::cout << "Preparing for callback...";
		std::cout << std::endl;
		break;
	case RASCS_WaitForModemReset:
		std::cout << "RASCS_WaitForModemReset = " << rasconnstate;
		std::cout << "Waiting for modem reset...";
		std::cout << std::endl;
		break;
	case RASCS_WaitForCallback:
		std::cout << "RASCS_WaitForCallback = " << rasconnstate;
		std::cout << "Waiting for callback...";
		std::cout << std::endl;
		break;
	case RASCS_Projected:
		std::cout << "RASCS_Projected = " << rasconnstate;
		std::cout << "Projection completed.";
		std::cout << std::endl;
		break;
	case RASCS_StartAuthentication:// Windows 95 only
		std::cout << "RASCS_StartAuthentication = " << rasconnstate;
		std::cout << "Starting authentication...";
		std::cout << std::endl;
		break;
	case RASCS_CallbackComplete:   // Windows 95 only
		std::cout << "RASCS_CallbackComplete = " << rasconnstate;
		std::cout << "Callback complete.";
		std::cout << std::endl;
		break;
	case RASCS_LogonNetwork:   // Windows 95 only
		std::cout << "RASCS_LogonNetwork = " << rasconnstate;
		std::cout << "Login to the network.";
		std::cout << std::endl;
		break;
	case RASCS_SubEntryConnected:
		std::cout << "RASCS_SubEntryConnected = " << rasconnstate;
		std::cout << "Subentry connected.";
		std::cout << std::endl;
		break;
	case RASCS_SubEntryDisconnected:
		std::cout << "RASCS_SubEntryDisconnected = " << rasconnstate;
		std::cout << "Subentry disconnected.";
		std::cout << std::endl;
		break;
		//PAUSED STATES:
	case RASCS_Interactive:
		std::cout << "RASCS_Interactive = " << rasconnstate;
		std::cout << "In Paused state: Interactive mode.";
		std::cout << std::endl;
		break;
	case RASCS_RetryAuthentication:
		std::cout << "RASCS_RetryAuthentication = " << rasconnstate;
		std::cout << "In Paused state: Retry Authentication...";
		std::cout << std::endl;
		break;
	case RASCS_CallbackSetByCaller:
		std::cout << "RASCS_CallbackSetByCaller = " << rasconnstate;
		std::cout << "In Paused state: Callback set by Caller.";
		std::cout << std::endl;
		break;
	case RASCS_PasswordExpired:
		std::cout << "RASCS_PasswordExpired = " << rasconnstate;
		std::cout << "In Paused state: Password has expired...";
		std::cout << std::endl;
		break;
	case RASCS_Connected: // = RASCS_DONE:
		std::cout << "RASCS_Connected = " << rasconnstate;
		std::cout << "#########Connection completed.";
		//SetEvent(gEvent_handle);
		std::cout << std::endl;
		break;
	case RASCS_Disconnected:
		std::cout << "RASCS_Disconnected = " << rasconnstate;
		std::cout << "Disconnecting...";
		std::cout << std::endl;
		break;
	default:
		std::cout << "Unknown Status = " << rasconnstate;
		std::cout << "What are you going to do about it?";
		std::cout << std::endl;
		break;
	}

}

bool Vpn::disconnect(const wchar_t * entryname)
{
	RASCONN conn;
	bool ok = getEntryConnection(entryname, conn);
	if (!ok)return false;
	else
	{
		DWORD ret = RasHangUp(conn.hrasconn);
		if (ret == ERROR_SUCCESS) {
			return true;
		}
		else 
		{
			return false;
		}
	}
}

bool Vpn::getEntryConnection(const wchar_t * entryname, RASCONN& conn)
{
	RASCONN arr[100];
	DWORD arr_size = sizeof(arr);
	ZeroMemory(&arr, arr_size);
	arr[0].dwSize = sizeof(RASCONN);
	
	DWORD number_of_connection = 0;
	DWORD ret=RasEnumConnections(arr, &arr_size, &number_of_connection);

	bool ok = false;
	for (DWORD i = 0; i < number_of_connection; i++) {
		RASCONN temp = arr[i];
		if (wcscmp(entryname, temp.szEntryName) == 0) {
			conn = temp;
			ok = true;
			break;
		}
	}
	return ok;
}

bool Vpn::deleteEntry(const wchar_t * entryname)
{
	DWORD ret;
	ret = RasDeleteEntry(NULL, entryname);
	return ret==0;
}

Vpn::Vpn()
{
}


Vpn::~Vpn()
{
}
