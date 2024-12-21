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
	virtual BOOL OnConnectionRequest() override;
	virtual void* OnAccept(ULONGLONG id) override;
	virtual void OnRelease(ULONGLONG id) override;
	virtual void OnRecv(ULONGLONG id, Packet* pPacket) override;
	virtual void OnError(ULONGLONG id, int errorType, Packet* pRcvdPacket) override;
	virtual void OnPost(void* order) override;
	cpp_redis::client* GetRedisClient();

	// Monitorable Override
	virtual void OnMonitor() override;
	WCHAR ipStr_[16];
	SHORT port_;
	DWORD redisClientIdx_;
	HANDLE hTimerQ_;

	WCHAR ChatServerIpStr_[16];
	SHORT ChatServerPort_;
	CMClient* pLanClient_;
	static inline HMonitor monitor;
	LONG authTPS_ = 0;
	ULONGLONG acceptTotal_ = 0;
};

