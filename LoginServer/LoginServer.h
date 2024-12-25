#pragma once
#include <cpp_redis/cpp_redis>
#include "NetServer.h"
#include "Monitorable.h"
#include "CMClient.h"
#include "HMonitor.h"
#pragma comment (lib, "cpp_redis.lib")
#pragma comment (lib, "tacopie.lib")
#pragma comment (lib, "ws2_32.lib")
class LoginServer : public Monitorable, public NetServer
{
public:
	LoginServer();
	void Start();
private:
	virtual BOOL OnConnectionRequest(const SOCKADDR_IN* pSockAddrIn) override;
	virtual void* OnAccept(ULONGLONG id) override;
	virtual void OnRelease(ULONGLONG id) override;
	virtual void OnRecv(ULONGLONG id, Packet* pPacket) override;
	virtual void OnError(ULONGLONG id, int errorType, Packet* pRcvdPacket) override;
	virtual void OnPost(void* order) override;
	virtual void OnLastTaskBeforeAllWorkerThreadEndBeforeShutDown() override; // 일반적으로 DB스레드에대한 PQCS를 쏠때 사용할것이다
	virtual void OnResourceCleanAtShutDown() override;

	// Monitorable Override
	virtual void OnMonitor() override;
	WCHAR ipStr_[16];
	SHORT port_;
    SOCKADDR_IN DummyIP1Point2_;
    SOCKADDR_IN DummyIP2Point2_;
	int bLoopBackTest_;

	SHORT ChatServerPort_;
	CMClient* pLanClient_;
	MonitoringUpdate* pConsoleMonitor_;
	static inline HMonitor monitor;
	ULONGLONG acceptTotal_ = 0;
	alignas(64) LONG authTPS_ = 0;
};

