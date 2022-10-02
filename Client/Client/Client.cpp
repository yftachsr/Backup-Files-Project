#include "Client.h"

Client::Client() {
	Networking net();
}

bool Client::start() {

	if (!parseTransferInfo())
		return false;
	bool infoExists = fileHandler.fileExists(INFO_FILE);

	if (!net.connectToServer())
		return false;
	
	if (!infoExists) {
		if (!registerRequest())
			return false;
	}	
	else {
		if (!parseClientInfo())
			return false;
	}
		
	if (!sendPublicKey())
		return false;
	
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

	uint8_t* payload;
	uint32_t payloadSize;
	if (!receiveResponse(CODE_RES_AES, payload, payloadSize))
		return false;
	memcpy(&res.clientID, payload, UUID_SIZE);
	if (!validateId(res.clientID)) {
		std::cerr << "Received incorrect id from server: \n";
		hexify(reinterpret_cast<const unsigned char*>(res.clientID), sizeof(res.clientID));
		return false;
	}
	payload += UUID_SIZE;
	res.encryptedAES = new uint8_t[payloadSize - UUID_SIZE];
	memcpy(&res.encryptedAES, payload, sizeof(res.encryptedAES));
	std::string aesKeystr = rsapriv.decrypt(reinterpret_cast<const char*>(res.encryptedAES)
		, sizeof(res.encryptedAES)); // Decrypt aes key
	memcpy(aesKey, aesKeystr.c_str(), aesKeystr.size());

	delete[] payload;

	return true;
}

bool Client::receiveResponse(const size_t expectedCode, 
	uint8_t*& payload,uint32_t& payloadSize) {

	ResponseHeader header;
	payload = nullptr;
	uint8_t buff[PACKET_SIZE];

	if (!net.receiveData(buff, PACKET_SIZE)) {
		std::cerr << "Failed to receive response from server" << std::endl;
		return false;
	}

	memcpy(&header, buff, sizeof(ResponseHeader));
	if (!validateHeader(header, expectedCode)) 
		return false;
	
	if (header.payloadsize = 0)
		return true;

	payloadSize = header.payloadsize;
	payload = new uint8_t[payloadSize];
	uint8_t* ptr = static_cast<uint8_t*>(buff) + sizeof(header);
	size_t recvBytes = PACKET_SIZE - sizeof(header);
	if (recvBytes < payloadSize)
		recvBytes = payloadSize;
	memcpy(payload, ptr, recvBytes);
	ptr = payload + recvBytes;
	while (recvBytes < payloadSize) {
		size_t toRead = payloadSize - recvBytes;
		if (toRead > PACKET_SIZE)
			toRead = PACKET_SIZE;
		if (!net.receiveData(buff, toRead)) {
			std::cerr << "Failed to receive response from server" << std::endl;
			delete[] payload;
			payload = nullptr;
			payloadSize = 0;
			return false;
		}
		memcpy(ptr, buff, toRead);
		recvBytes += toRead;
		ptr += toRead;
	}
	return true;
}

bool Client::validateId(uint8_t* id) {
	for (size_t i = 0; i < UUID_SIZE; i++)
		if (clientID[i] != id[i])
			return false;
	return true;
}

void Client::hexify(const unsigned char* buffer, unsigned int length) {
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}

bool Client::saveClientInfo() {

	std::fstream file;
	if (!fileHandler.openFile(file, INFO_FILE, true)) {
		std::cerr << "Failed to open/create info file " << INFO_FILE << std::endl;
		return false;
	}
	std::string name = username.append("\n");
	if (!fileHandler.writeToFile(file, reinterpret_cast<const uint8_t*>(name.c_str()), name.size())) {
		std::cerr << "Failed to write to info file " << INFO_FILE << std::endl;
		return false;
	}

	if (!fileHandler.writeHex(file, reinterpret_cast
		<const unsigned char*>(clientID),sizeof(clientID))) {
		std::cerr << "Failed to write to info file " << INFO_FILE << std::endl;
		return false;
	}

	std::string base64key = Base64Wrapper::encode(privateKey);
	if (!fileHandler.writeToFile(file, reinterpret_cast<const uint8_t*>(base64key.c_str()),base64key.size())) {
		std::cerr << "Failed to write to info file " << INFO_FILE << std::endl;
		return false;
	}

	file.close();
	return true;
}

bool Client::parseClientInfo() {

	std::fstream file;
	if (fileHandler.openFile(file, INFO_FILE, false)) {
		std::cerr << "Failed to open info file " << INFO_FILE << " for reading" << std::endl;
		return false;
 	}
	
	if (fileHandler.readLine(file, username)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}

	std::string id;
	if (fileHandler.readLine(file, id)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}
	memcpy(&clientID, id.c_str(), UUID_SIZE);

	std::string key;
	if(fileHandler.readLine(file, key)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}
	privateKey = Base64Wrapper::decode(key);

	file.close();
	return true;
}