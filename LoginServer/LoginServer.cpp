#include <WinSock2.h>
#include <windows.h>

#include <stdlib.h>
#include "LoginServer.h"
#include "QueryFactory.h"
#include "Packet.h"
#include "CommonProtocol.h"
#include "Parser.h"
#include "Assert.h"
#include "MyJob.h"
#include "Logger.h"
#pragma comment(lib,"libmysql.lib")

using cpp_redis::client;
LoginServer::LoginServer()
    :NetServer{L"LoginServerConfig.txt"}
{}

void LoginServer::Start()
{
    char* pStart;
    char* pEnd;
    PARSER psr = CreateParser(L"LoginServerConfig.txt");

    GetValue(psr, L"BIND_IP", (PVOID*)&pStart, (PVOID*)&pEnd);
    unsigned long long stringLen = (pEnd - pStart) / sizeof(WCHAR);
    wcsncpy_s(ipStr_, _countof(ipStr_) - 1, (const WCHAR*)pStart, stringLen);
    ipStr_[stringLen] = 0;

    GetValue(psr, L"BIND_PORT", (PVOID*)&pStart, nullptr);
    port_ = (short)_wtoi((LPCWSTR)pStart);

    GetValue(psr, L"CHATSERVER_IP", (PVOID*)&pStart, (PVOID*)&pEnd);
    stringLen = (pEnd - pStart) / sizeof(WCHAR);
    wcsncpy_s(ChatServerIpStr_, _countof(ipStr_) - 1, (const WCHAR*)pStart, stringLen);
    ipStr_[stringLen] = 0;

    GetValue(psr, L"CHATSERVER_PORT", (PVOID*)&pStart, nullptr);
    ChatServerPort_ = (short)_wtoi((LPCWSTR)pStart);
    ReleaseParser(psr);

    redisClientIdx_ = TlsAlloc();
    TLS_ASSERT(redisClientIdx_);


	for (DWORD i = 0; i < IOCP_WORKER_THREAD_NUM_; ++i)
		ResumeThread(hIOCPWorkerThreadArr_[i]);

    ResumeThread(hAcceptThread_);

    MonitoringUpdate* pMonitor = new MonitoringUpdate{ hcp_,1000,3 };
    Timer::Reigster_UPDATE(pMonitor);
    pMonitor->RegisterMonitor(this);

    pLanClient_ = new CMClient{ L"LoginLanClientConfig.txt",SERVERNUM::LOGIN };
    pLanClient_->Start();
    Timer::Start();
}

BOOL LoginServer::OnConnectionRequest()
{
    return TRUE;
}

void* LoginServer::OnAccept(ULONGLONG id)
{
    return nullptr;
}

void LoginServer::OnRelease(ULONGLONG id)
{
}

void MAKE_CS_LOGIN_RES_LOGIN(ULONGLONG id, INT64 accountNo, BYTE status, WCHAR* pID,
    WCHAR* pNickName, WCHAR* pGameServerIP, SHORT gamePort, WCHAR* pChatServerIP, SHORT chatServerPort, SmartPacket& sp)
{
    *sp << (WORD)en_PACKET_CS_LOGIN_RES_LOGIN << accountNo << status;
    sp->PutData((char*)pID, 20 * sizeof(WCHAR));
    sp->PutData((char*)pNickName, 20 * sizeof(WCHAR));
    sp->PutData((char*)pGameServerIP, 16 * sizeof(WCHAR));
    *sp << gamePort;
    sp->PutData((char*)pChatServerIP, 16 * sizeof(WCHAR));
    *sp << chatServerPort;
}

void LoginServer::OnRecv(ULONGLONG id, Packet* pPacket)
{
    WORD Type;
    INT64 accountNo;

    *pPacket >> Type;
    if (Type != en_PACKET_CS_LOGIN_REQ_LOGIN)
    {
        LOG(L"ERROR", SYSTEM, TEXTFILE, L"OnRecv PacketTypeErr Type is Not en_PACKET_CS_LOGIN_REQ_LOGIN, Type : %d", Type);
        __debugbreak();
    }

    *pPacket >> accountNo;
    char* pSessionKey = pPacket->GetPointer(64);

    QueryFactory::GetInstance()->MAKE_QUERY("SELECT sessionkey FROM accountdb.sessionkey WHERE accountno = %d", accountNo);
    MYSQL_RES_PTR readTokenRet = QueryFactory::GetInstance()->ExecuteReadQuery();

    MYSQL_ROW sqlRow;
    sqlRow = mysql_fetch_row(&*readTokenRet);
    if (!sqlRow)
    {
        LOG(L"ERROR", SYSTEM, TEXTFILE, L"mysql_fetch_row Error At Onrecv, Failed To Get SessionKey");
        __debugbreak();
    }

    // 워커스레드에서 직접 레디스에 인증토큰을 넣음 
    client* pClient = GetRedisClient();

    pClient->set(std::to_string(accountNo), std::string{ pSessionKey ,64 });
    pClient->expire(std::to_string(accountNo), 10);
    pClient->sync_commit();

    WCHAR ID[20];
    WCHAR NICK[20];

    QueryFactory::GetInstance()->MAKE_QUERY("SELECT userid,usernick FROM accountdb.account WHERE accountno = %d", accountNo);
    MYSQL_RES_PTR readAccountInfoRet = QueryFactory::GetInstance()->ExecuteReadQuery();
    sqlRow = mysql_fetch_row(&*readAccountInfoRet);

    size_t ret;
    ASSERT_NOT_ZERO(mbstowcs_s(&ret, ID, _countof(ID), sqlRow[0], SIZE_MAX));
    ASSERT_NOT_ZERO(mbstowcs_s(&ret, NICK, _countof(NICK), sqlRow[1], SIZE_MAX));

    // 사용자에게 로그인 승인
    SmartPacket sp = PACKET_ALLOC(Net);
    MAKE_CS_LOGIN_RES_LOGIN(id, accountNo, 1, ID, NICK, ChatServerIpStr_, ChatServerPort_, ChatServerIpStr_, ChatServerPort_, sp);
    SendPacket(id, sp.GetPacket());
    PACKET_FREE(pPacket);
    InterlockedIncrement(&authTPS_);
}

void LoginServer::OnError(ULONGLONG id, int errorType, Packet* pRcvdPacket)
{
}

void LoginServer::OnPost(void* order)
{
}

cpp_redis::client* LoginServer::GetRedisClient()
{
    client* pClient = (client*)TlsGetValue(redisClientIdx_);
    if (!pClient)
    {
        pClient = new client;
        pClient->connect();
        TlsSetValue(redisClientIdx_, pClient);
    }
    return pClient;
}

void LoginServer::OnMonitor()
{
    FILETIME ftCreationTime, ftExitTime, ftKernelTime, ftUsertTime;
    FILETIME ftCurTime;
    GetProcessTimes(GetCurrentProcess(), &ftCreationTime, &ftExitTime, &ftKernelTime, &ftUsertTime);
    GetSystemTimeAsFileTime(&ftCurTime);

    ULARGE_INTEGER start, now;
    start.LowPart = ftCreationTime.dwLowDateTime;
    start.HighPart = ftCreationTime.dwHighDateTime;
    now.LowPart = ftCurTime.dwLowDateTime;
    now.HighPart = ftCurTime.dwHighDateTime;


    ULONGLONG ullElapsedSecond = (now.QuadPart - start.QuadPart) / 10000 / 1000;

    ULONGLONG temp = ullElapsedSecond;

    ULONGLONG ullElapsedMin = ullElapsedSecond / 60;
    ullElapsedSecond %= 60;

    ULONGLONG ullElapsedHour = ullElapsedMin / 60;
    ullElapsedMin %= 60;

    ULONGLONG ullElapsedDay = ullElapsedHour / 24;
    ullElapsedHour %= 24;


    monitor.UpdateCpuTime(nullptr, nullptr);
    monitor.UpdateQueryData();

    ULONGLONG acceptTPS = InterlockedExchange(&acceptCounter_, 0);
    ULONGLONG disconnectTPS = InterlockedExchange(&disconnectTPS_, 0);
    ULONGLONG recvTPS = InterlockedExchange(&recvTPS_, 0);
    LONG sendTPS = InterlockedExchange(&sendTPS_, 0);
    LONG authTPS = InterlockedExchange(&authTPS_, 0);
    LONG sessionNum = InterlockedXor(&lSessionNum_, 0);
    LONG packetPoolUseCount = InterlockedXor(&Packet::packetPool_.AllocSize_, 0);
    acceptTotal_ += acceptTPS;

    double processPrivateMByte = monitor.GetPPB() / (1024 * 1024);

    printf(
        "Elapsed Time : %02lluD-%02lluH-%02lluMin-%02lluSec\n"
        "MonitorServerConnected : %s\n"
        "Packet Pool Alloc Capacity : %d\n"
        "Packet Pool Alloc UseSize: %d\n"
        "Accept TPS: %llu\n"
        "Accept Total : %llu\n"
        "Disconnect TPS: %llu\n"
        "Recv Msg TPS: %llu\n"
        "Send Msg TPS: %d\n"
        "Auth TPS : %d\n"
        "Session Num : %d\n"
        "----------------------\n"
        "Process Private MBytes : %.2lf\n"
        "Process NP Pool KBytes : %.2lf\n"
        "Process CPU Time : %.2f\n\n",
        ullElapsedDay, ullElapsedHour, ullElapsedMin, ullElapsedSecond,
        (pLanClient_->bLogin_ == TRUE) ? "True" : "False",
        Packet::packetPool_.capacity_ * Bucket<Packet, false>::size,
        packetPoolUseCount,
        acceptTPS,
        acceptTotal_,
        disconnectTPS,
        recvTPS,
        sendTPS,
        authTPS,
        sessionNum,
        processPrivateMByte,
        monitor.GetPNPB() / 1024,
        monitor._fProcessTotal
    );

    if (pLanClient_->bLogin_ == FALSE)
        return;

    time_t curTime;
    time(&curTime);
#pragma warning(disable : 4244) // 프로토콜이 4바이트를 받고 상위4바이트는 버려서 별수없음
    pLanClient_->SendToMonitoringServer(LOGIN, dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN, 1, curTime);
    pLanClient_->SendToMonitoringServer(LOGIN, dfMONITOR_DATA_TYPE_LOGIN_SERVER_CPU, monitor._fProcessTotal, curTime);
    pLanClient_->SendToMonitoringServer(CHAT, dfMONITOR_DATA_TYPE_LOGIN_SERVER_MEM, processPrivateMByte, curTime);
    pLanClient_->SendToMonitoringServer(CHAT, dfMONITOR_DATA_TYPE_LOGIN_SESSION, sessionNum, curTime);
    pLanClient_->SendToMonitoringServer(CHAT, dfMONITOR_DATA_TYPE_LOGIN_AUTH_TPS, authTPS, curTime);
    pLanClient_->SendToMonitoringServer(CHAT, dfMONITOR_DATA_TYPE_LOGIN_PACKET_POOL, packetPoolUseCount, curTime);
#pragma warning(default : 4244)
}


