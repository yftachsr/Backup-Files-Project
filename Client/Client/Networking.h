#pragma once
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")

#include <cstdint>
#include <string>
#include <iostream>

class Networking
{
	uint16_t port;
	std::string addr;
	SOCKET sock;
public:
	Networking();
	bool connectToServer();
	void setIPPort(const std::string&, const uint16_t&);

};

