#pragma once
#pragma once
#include <cpp_redis/cpp_redis>
#include "GameServer.h"
#include "Monitorable.h"
#include "CMClient.h"
#include "HMonitor.h"
#pragma comment (lib, "cpp_redis.lib")
#pragma comment (lib, "tacopie.lib")
#pragma comment (lib, "ws2_32.lib")

class LoginContent;

class LoginServer : public GameServer
{
public:
	LoginServer(WCHAR* pIP, USHORT port, DWORD iocpWorkerNum, DWORD cunCurrentThreadNum, BOOL bZeroCopy, LONG maxSession, LONG maxUser, BYTE packetCode, BYTE packetfixedKey, USHORT chatPort, BOOL bLoopBackTest, CMClient* pMonitorLanClient);
	~LoginServer();
	void Start();
private:
	BOOL OnConnectionRequest(const WCHAR* pIP, const USHORT port) override;
	void RegisterMonitorLanClient(CMClient* pClient);
	virtual void* OnAccept(void* pPlayer) override;
	virtual void OnError(ULONGLONG id, int errorType, Packet* pRcvdPacket) override;
	virtual void OnPost(void* order) override;
	virtual void OnLastTaskBeforeAllWorkerThreadEndBeforeShutDown() override; // �Ϲ������� DB�����忡���� PQCS�� �� ����Ұ��̴�

	// Monitorable Override
	virtual void OnMonitor() override;
//	WCHAR ipStr_[16];
public:
	SOCKADDR_IN DummyIP1Point2_;
	SOCKADDR_IN DummyIP2Point2_;
	BOOL bLoopBackTest_;
	USHORT ChatServerPort_;
private:
	CMClient* pLanClient_ = nullptr;
	MonitoringUpdate* pConsoleMonitor_;
	static inline HMonitor monitor;
	ULONGLONG acceptTotal_ = 0;
public:
	alignas(64) LONG authTPS_ = 0;
private:
	LoginContent* pLoginContent_;
};


