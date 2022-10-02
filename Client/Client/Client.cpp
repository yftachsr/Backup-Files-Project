#include "Client.h"

Client::Client() {
	Networking net();
}

bool Client::start() {

	if (!parseTransferInfo())
		return false;
	bool infoExists = fileHandler.fileExists(INFO_FILE);
	if (!infoExists)
		registerRequest();
	else
		parseClientInfo();

	sendPublicKey();
	
	if(!infoExists)
		saveClientInfo(); // By now we have all the information needed to save on the disk
}

bool Client::parseTransferInfo() {

	std::fstream file;
	if (!fileHandler.openFile(file, TRANSFER_FILE, false)) {
		std::cerr << "Failed to open " << TRANSFER_FILE
			<< " for reading" << std::endl;
		return false;
	}
	std::string line;
	// parse server ip and port
	if (!fileHandler.readLine(file, line)) {
		std::cerr << "Failed to read a line from " << TRANSFER_FILE << std::endl;
		return false;
	}
	std::string addr;
	uint16_t port;
	if (!extractIPPort(line, addr, port)) {
		std::cerr << "Failed to parse ip and port from " << TRANSFER_FILE << std::endl;
		return false;
	}
	net.setIPPort(addr, port);

	// parse username
	if (!fileHandler.readLine(file, line)) {
		std::cerr << "Failed to read a line from " << TRANSFER_FILE << std::endl;
		return false;
	}
	
	if (line.size() >= NAME_SIZE) {
		std::cerr << "Invalid name length" << std::endl;
		return false;
	}
	username = line;

	// parse file path
	if (!fileHandler.readLine(file, line)) {
		std::cerr << "Failed to read a line from " << TRANSFER_FILE << std::endl;
		return false;
	}

	if (!fileHandler.fileExists(line)) {
		std::cerr << "Specified file in " << TRANSFER_FILE << " doesn't exist" << std::endl;
		return false;
	}
	filePath = line;
	file.close();
	return true;
}

bool Client::extractIPPort(std::string str, std::string& addr, uint16_t& port) {
	size_t pos = str.find(':');
	if (pos == std::string::npos) {
		std::cerr << "Invalid ip port format: missing ':'" << std::endl;
		return false;
	}
	addr = str.substr(0, pos);
	try {
		port = std::stoi(str.substr(pos + 1));
	}
	catch (std::exception&) {
		return false;
	}
	return true;
}

bool Client::registerRequest() {

	RegisterRequest req = RegisterRequest();
	RegisterResponse res = RegisterResponse();

	req.header.payloadSize = NAME_SIZE;
	strcpy_s(reinterpret_cast<char*>(req.name), NAME_SIZE, username.c_str());
	if (!net.sendData(reinterpret_cast<const uint8_t* const>(&req), sizeof(req))) {
		std::cerr << "Failed to send request to server" << std::endl;
		return false;
	}

	if (!net.receiveData(reinterpret_cast<uint8_t* const>(&res), sizeof(res))) {
		std::cerr << "Failed to receive response from server" << std::endl;
		return false;
	}
	
	if (!validateHeader(res.header, CODE_RES_REGISTER))
		return false;

	memcpy(&clientID, &res.clientID, UUID_SIZE);

	return true;
}

bool Client::validateHeader(const ResponseHeader& header, const size_t expectedCode) {

	if (header.code == CODE_ERROR) {
		std::cerr << "Error code " << CODE_ERROR << " received from server" << std::endl;
		return false;
	}

	if (header.code == expectedCode) {
		std::cerr << "Unexpected code received from server " << header.code
			<< ". Expected code " << expectedCode << std::endl;
		return false;
	}

	uint32_t expectedSize;
	switch (header.code) {

	case CODE_RES_REGISTER:
		expectedSize = sizeof(RegisterResponse) - sizeof(ResponseHeader);
		break;
	case CODE_RES_FILE_CRC:
		expectedSize = sizeof(FileResponse) - sizeof(ResponseHeader);
		break;
	default:
		return true;
	}

	if (header.payloadsize != expectedSize) {
		std::cerr << "Unexpected payload size received from server " << header.payloadsize
			<< ". Expected " << expectedSize << std::endl;
		return false;
	}
	return true;
}

bool Client::sendPublicKey() {
	
	PublicKeyRequest req = PublicKeyRequest();
	PublicKeyResponse res = PublicKeyResponse();

	req.header.payloadSize = NAME_SIZE + PUBLIC_KEY_SIZE;
	memcpy(&req.header.clientID, &clientID, UUID_SIZE);
	memcpy(&req.name, username.c_str(), NAME_SIZE);

	// Generate public and private RSA key
	RSAPrivateWrapper rsapriv;
	char pubkeybuff[PUBLIC_KEY_SIZE];
	rsapriv.getPublicKey(pubkeybuff, PUBLIC_KEY_SIZE);
	memcpy(&req.publicKey, pubkeybuff, PUBLIC_KEY_SIZE);
	privateKey = rsapriv.getPrivateKey();

	if (!net.sendData(reinterpret_cast<const uint8_t* const>(&req), sizeof(req))) {
		std::cerr << "Failed to send request to server" << std::endl;
		return false;
	}




	return true;
}

bool Client::receiveResponse(const size_t expectedCode, 
	uint8_t*& payload,size_t& payloadSize) {

	ResponseHeader header;
	payload = nullptr;
	uint8_t buff[PACKET_SIZE];

	if (!net.receiveData(buff, PACKET_SIZE)) {
		std::cerr << "Failed to receive response from server" << std::endl;
		return false;
	}

	memcpy(&header, buff, sizeof(ResponseHeader));

	
}