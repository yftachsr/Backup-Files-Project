#pragma once
#include <string>
#include <iostream>
#include "Protocol.h"
#include "FileHandler.h"
#include "Networking.h"

#define INFO_FILE "me.info"
#define TRANSFER_FILE "transfer.info"

class Client
{
	uint8_t clientID[UUID_SIZE];
	std::string username;
	std::string filePath;
	uint8_t publicKey[PUBLICKEY_SIZE];
	uint8_t aesKey[AESKEY_SIZE];
	FileHandler fileHandler;
	Networking net;
	Client();
	void clientProcedure();
	bool registerRequest();
	bool start();
	bool parseTransferInfo();
	bool extractIPPort(std::string, std::string&, uint16_t&);
};

