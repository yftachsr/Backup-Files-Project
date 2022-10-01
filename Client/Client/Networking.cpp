#include "Networking.h"

Networking::Networking() {

	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		std::cerr << "An error has occurred while initiating Winsock: "
			<< wsaData.szSystemStatus << std::endl;
		WSACleanup();
		terminate();
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "An error has occurred while trying to create "
			<< "a socket: " << WSAGetLastError() << std::endl;
		WSACleanup();
		terminate();
	}	
}

void Networking::setIPPort(const std::string& addr, const uint16_t& port) {
	this->addr = addr;
	this->port = port;
}

bool Networking::connectToServer() {
	SOCKADDR_IN sa;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(addr.c_str());
	int ret = connect(sock, (SOCKADDR*)&sa, sizeof(sa));
	if (ret != 0) {
		std::cerr << "Failed to connect to server\n" << WSAGetLastError();
		closesocket(sock);
		WSACleanup();
		return false;
	} 
}
