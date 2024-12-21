#include <WinSock2.h>
#include <Windows.h>
#include "LoginServer.h"
LoginServer g_ls;
#include <iostream>

int main()
{
	g_ls.Start();
	Sleep(INFINITE);
	//! or client.commit(); for asynchronous call}
}

