// ConsoleApplication1.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Vpn.h"
#include <iostream>
#include <string>

int main()
{
	Vpn vpn;
	vpn.createvpn(L"youxi_dali", L"104.207.148.70", L"", L"", L"l2tppass", l2tp_psk);
	std::cout << L"123456789adasdasd";
    return 0;
}

