#pragma once
#include <cstdint>

#define VERSION 3
#define UUID_SIZE 16
#define PUBLICKEY_SIZE 160
#define AESKEY_SIZE 16
#define NAME_SIZE 255
const size_t CODE_REQ_REGISTER = 1100;

#pragma pack(push, 1)
struct RequestHeader {
	uint8_t clientID[UUID_SIZE];
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	RequestHeader(const uint16_t code) : clientID{0},
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
	RegisterRequest() : header(CODE_REQ_REGISTER), name("\0") {}
};

struct RegisterResponse {
	ResponseHeader header;
	uint8_t clientID[UUID_SIZE];
};

#pragma pack(pop)