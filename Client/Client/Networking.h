#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <cstdint>
#include <string>
#include <iostream>
#include "Protocol.h"

class Networking
{
	uint16_t port;
	std::string addr;
	SOCKET sock;
public:
	Networking();
	bool connectToServer();
	void setIPPort(const std::string&, const uint16_t&);
	bool sendData(const uint8_t* const, const size_t);
	bool receiveData(uint8_t* const, const size_t);
	void disconnetServer();
};

