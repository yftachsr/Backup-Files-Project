#pragma once
#include <cstdint>

#define PACKET_SIZE 1024
#define VERSION 3
#define UUID_SIZE 16
#define PUBLIC_KEY_SIZE 160
#define AESKEY_SIZE 16
#define NAME_SIZE 255
#define TRYS_NUM 3

const size_t CODE_RES_REGISTER = 2100;
const size_t CODE_REQ_REGISTER = 1100;
const size_t CODE_ERROR = -1;
const size_t CODE_REQ_RES = 1101;
const size_t CODE_REQ_FILE = 1103;
const size_t CODE_REQ_CRC_VALID = 1104;
const size_t CODE_REQ_CRC_RETRY = 1105;
const size_t CODE_REQ_CRC_FAIL = 1106;
const size_t CODE_RES_AES = 2102;
const size_t CODE_RES_FILE_CRC = 2103;
const size_t CODE_RES_MESSAGE = 2104;


#pragma pack(push, 1)
struct RequestHeader {
	uint8_t clientID[UUID_SIZE];
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	RequestHeader(const uint16_t code) : clientID{'\0'},
		version(VERSION), code(code), payloadSize(0) {}
	RequestHeader(const uint8_t* id, const uint16_t code) : version(VERSION),
		code(code), payloadSize(0) {
		for (int i = 0; i < UUID_SIZE; i++)
			clientID[i] = id[i];
	}
};

struct ResponseHeader {
	uint8_t version;
	uint16_t code;
	uint32_t payloadsize;
	ResponseHeader() : version(0), code(0), payloadsize(0) {}
};

struct RegisterRequest {
	RequestHeader header;
	uint8_t name[NAME_SIZE];
	RegisterRequest() : header(CODE_REQ_REGISTER), name{ '\0' } {}
};

struct RegisterResponse {
	ResponseHeader header;
	uint8_t clientID[UUID_SIZE];
};

struct PublicKeyRequest {
	RequestHeader header;
	uint8_t name[NAME_SIZE];
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	PublicKeyRequest() : header(CODE_REQ_RES), name{ '\0' }, publicKey{'\0'} {}
};

struct PublicKeyResponse {
	ResponseHeader header;
	uint8_t clientID[UUID_SIZE];
	uint8_t* encryptedAES;
	~PublicKeyResponse() { delete[] encryptedAES; }
};

struct FileResponse {
	ResponseHeader header;
	uint8_t clientID[UUID_SIZE];
	uint8_t fileName[NAME_SIZE];
	uint32_t cksum;
};

#pragma pack(pop)