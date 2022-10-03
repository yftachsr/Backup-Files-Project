#pragma once
#include <string>
#include <iostream>
#include <filesystem>
#include "Protocol.h"
#include "FileHandler.h"
#include "Networking.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "crc.h"

#define INFO_FILE "me.info"
#define TRANSFER_FILE "transfer.info"

class Client
{
	uint8_t clientID[UUID_SIZE];
	std::string username;
	std::string filePath;
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	std::string privateKey;
	uint8_t aesKey[AESKEY_SIZE];
	FileHandler fileHandler;
	Networking net;	
	bool registerRequest();	
	bool parseTransferInfo();
	bool extractIPPort(std::string, std::string&, uint16_t&);
	bool validateHeader(const ResponseHeader&, const size_t);
	bool sendPublicKey();
	bool receiveResponse(const size_t, uint8_t*&, uint32_t&);
	void hexify(const unsigned char*, unsigned int);
	bool validateId(uint8_t*);
	bool saveClientInfo();
	bool parseClientInfo();
	bool sendFile();
public:
	Client();
	~Client();
	bool start();
};

