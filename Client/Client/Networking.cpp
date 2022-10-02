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
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.S_un.S_addr, addr.c_str(), sizeof(sa.sin_addr.S_un.S_addr));
	int ret = connect(sock, (SOCKADDR*)&sa, sizeof(sa));
	if (ret != 0) {
		std::cerr << "Failed to connect to server\n" << WSAGetLastError() << std::endl;
		closesocket(sock);
		WSACleanup();
		return false;
	} 

	return true;
}

bool Networking::sendData(const uint8_t* const buff, const size_t size) {

	size_t bytesLeft = size;
	const uint8_t* ptr = buff;
	while (bytesLeft > 0) {
		uint8_t temp[PACKET_SIZE] = {0};
		size_t toSend = (bytesLeft > PACKET_SIZE) ? PACKET_SIZE : bytesLeft;
		memcpy(temp, ptr, toSend);
		const size_t sentBytes = send(sock, reinterpret_cast<char*>(temp), PACKET_SIZE, 0);
		if (sentBytes == SOCKET_ERROR)
			return false;
		ptr += sentBytes;
		bytesLeft = (bytesLeft < sentBytes) ? 0 : (bytesLeft - sentBytes);
	}
	return true;
}

bool Networking::receiveData(uint8_t* const buff, const size_t size) {

	uint8_t* ptr = buff;
	size_t bytesLeft = size;

	while (bytesLeft > 0) {
		uint8_t temp[PACKET_SIZE] = { 0 };
		size_t recvBytes = recv(sock, reinterpret_cast<char*>(temp), PACKET_SIZE, 0);
		if (recvBytes == SOCKET_ERROR)
			return false;
		size_t copyBytes = (bytesLeft > recvBytes) ? recvBytes : bytesLeft;
		memcpy(ptr, temp, copyBytes);
		ptr += copyBytes;
		bytesLeft = (bytesLeft < copyBytes) ? 0 : (bytesLeft - copyBytes);
	}
	return true;
}


