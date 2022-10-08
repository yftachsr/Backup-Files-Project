#include "Client.h"

/* Place files to send in the same folder of .cpp and .h files*/

Client::Client() {
	net = Networking();
}

Client::~Client() {
	net.disconnetServer();
}

bool Client::start() {

	if (!parseTransferInfo()) // Get server ip and port, username and file name to send
		return false;
	bool infoExists = fileHandler.fileExists(INFO_FILE);

	if (!net.connectToServer())
		return false;

	if (!infoExists) {
		if (!registerRequest())
			return false;
	}	
	else {
		std::cout << "Client already registered in the server" << std::endl;
		if (!parseClientInfo()) // Get username, id and public key
			return false;
	}
	
	if (!sendPublicKey())
		return false;
	
	if(!infoExists)
		saveClientInfo(); // By now we have all the information needed to save on the disk

	if (!sendFile())
		return false;
	return true;
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
	line.pop_back(); // remove \r
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
	filePath += line;
	file.close();
	return true;
}

bool Client::extractIPPort(std::string str, std::string& addr, uint16_t& port) {

	const int minPort = 1, maxPort = 65535;
	size_t pos = str.find(':');
	if (pos == std::string::npos) {
		std::cerr << "Invalid ip port format: missing ':'" << std::endl;
		return false;
	}
	addr = str.substr(0, pos);
	try {
		int portCheck = std::stoi(str.substr(pos + 1));
		if (portCheck < 1 || portCheck > maxPort) {
			std::cerr << "Invalid port" << std::endl;
			return false;
		}
		port = portCheck;
		std::cout << addr << ":" << std::stoi(str.substr(pos + 1)) << std::endl;
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
	memcpy(req.name, username.c_str(), NAME_SIZE);
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

	memcpy(clientID, res.clientID, UUID_SIZE);
	std::cout << "Client registered in the server with the username: " << req.name << std::endl;
	return true;
}

bool Client::validateHeader(const ResponseHeader& header, const size_t expectedCode) {

	if (header.code == CODE_ERROR) {
		std::cerr << "Error code " << CODE_ERROR << " received from server" << std::endl;
		return false;
	}

	if (header.code != expectedCode) {
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
	memcpy(req.header.clientID, clientID, UUID_SIZE);
	memcpy(req.name, username.c_str(), NAME_SIZE);

	// Generate public and private RSA key
	RSAPrivateWrapper rsapriv;
	char pubkeybuff[PUBLIC_KEY_SIZE];
	rsapriv.getPublicKey(pubkeybuff, PUBLIC_KEY_SIZE);
	memcpy(req.publicKey, pubkeybuff, PUBLIC_KEY_SIZE);
	privateKey = rsapriv.getPrivateKey();

	if (!net.sendData(reinterpret_cast<const uint8_t* const>(&req), sizeof(req))) {
		std::cerr << "Failed to send request to server" << std::endl;
		return false;
	}
	std::cout << "Public key was sent to the server" << std::endl;
	if (!receiveResponse(res))
		return false;
	
	if (!validateId(res.clientID)) {
		std::cerr << "Received incorrect id from server: \n";
		hexify(reinterpret_cast<const unsigned char*>(res.clientID), sizeof(res.clientID));
		return false;
	}
	std::string aesKeystr;

	aesKeystr = rsapriv.decrypt(reinterpret_cast<const char*>(res.encryptedAES)
		, res.header.payloadsize - UUID_SIZE); // Decrypt aes key
	
	memcpy(aesKey, aesKeystr.c_str(), aesKeystr.size());
	std::cout << "Symmetric key received from server" << std::endl;
	return true;
}

bool Client::receiveResponse(PublicKeyResponse& res) {

	uint8_t buff[PACKET_SIZE];

	if (!net.receiveData(buff, PACKET_SIZE)) {
		std::cerr << "Failed to receive response from server" << std::endl;
		return false;
	}
	memcpy(&res.header, buff, sizeof(ResponseHeader));

	if (!validateHeader(res.header, CODE_RES_AES))
		return false;

	if (res.header.payloadsize == 0 || res.header.payloadsize <= UUID_SIZE)
		return false;

	uint8_t* payload = new uint8_t[res.header.payloadsize];
	uint8_t* ptr = buff + sizeof(res.header);
	size_t recvBytes = PACKET_SIZE - sizeof(res.header);
	if (recvBytes > res.header.payloadsize)
		recvBytes = res.header.payloadsize;
	memcpy(payload, ptr, recvBytes);
	ptr = payload + recvBytes;
	while (recvBytes < res.header.payloadsize) {
		size_t toRead = res.header.payloadsize - recvBytes;
		if (toRead > PACKET_SIZE)
			toRead = PACKET_SIZE;
		if (!net.receiveData(buff, toRead)) {
			std::cerr << "Failed to receive response from server" << std::endl;
			delete[] payload;
			return false;
		}
		memcpy(ptr, buff, toRead);
		recvBytes += toRead;
		ptr += toRead;
	}
	ptr = payload;
	memcpy(res.clientID, ptr, UUID_SIZE);
	res.encryptedAES = new uint8_t[res.header.payloadsize - UUID_SIZE];
	ptr += UUID_SIZE;
	memcpy(res.encryptedAES, ptr, res.header.payloadsize - UUID_SIZE);

	delete[] payload;
	return true;
}

bool Client::receiveResponse(const size_t expectedCode, 
	uint8_t*& payload,uint32_t& payloadSize) {

	ResponseHeader header;
	uint8_t buff[PACKET_SIZE];

	if (!net.receiveData(buff, PACKET_SIZE)) {
		std::cerr << "Failed to receive response from server" << std::endl;
		return false;
	}

	memcpy(&header, buff, sizeof(ResponseHeader));
	if (!validateHeader(header, expectedCode)) 
		return false;
	
	if (header.payloadsize == 0)
		return true;

	payloadSize = header.payloadsize;
	payload = new uint8_t[payloadSize];
	uint8_t* ptr = static_cast<uint8_t*>(buff) + sizeof(header);
	size_t recvBytes = PACKET_SIZE - sizeof(header);
	if (recvBytes > payloadSize)
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

int Client::char2int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	throw std::invalid_argument("Invalid input string");
}

void Client::hex2bin(const char* src, char* target)
{
	while (*src && src[1])
	{
		*(target++) = char2int(*src) * 16 + char2int(src[1]);
		src += 2;
	}
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
	if (!fileHandler.openFile(file, INFO_FILE, false)) {
		std::cerr << "Failed to open info file " << INFO_FILE << " for reading" << std::endl;
		return false;
 	}
	
	if (!fileHandler.readLine(file, username)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}

	std::string idhex;
	if (!fileHandler.readLine(file, idhex)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}
	char id[UUID_SIZE];
	hex2bin(idhex.c_str(), id);
	memcpy(clientID, id, UUID_SIZE);

	std::string key;
	if(!fileHandler.readLine(file, key)) {
		std::cerr << "Failed to read info file " << INFO_FILE << std::endl;
		return false;
	}
	privateKey = Base64Wrapper::decode(key);

	file.close();
	return true;
}

bool Client::sendFile() {
	
	FileRequest req = FileRequest();
	FileResponse res = FileResponse();
	CRCRequest reqCrc = CRCRequest();
	
	memcpy(req.header.clientID, clientID, UUID_SIZE);
	std::string filename = fileHandler.extractFileName(filePath);
	memcpy(req.fileName, filename.c_str(), NAME_SIZE);
	memcpy(reqCrc.header.clientID, clientID, UUID_SIZE);
	memcpy(reqCrc.fileName, filename.c_str(), NAME_SIZE);
	reqCrc.header.payloadSize = NAME_SIZE;
	std::fstream file;
	uint32_t filesize = (uint32_t)std::filesystem::file_size(filePath);
	if (!fileHandler.openFile(file, filePath, false)) {
		std::cerr << "Failed to open file " << filePath << std::endl;
		return false;
	}

	uint8_t* filecon = new uint8_t[filesize];
	if (!fileHandler.readFromFile(file, filecon, filesize)) {
		std::cerr << "Failed to read from file " << filePath << std::endl;
		return false;
	}

	AESWrapper aes(reinterpret_cast<const unsigned char*>(aesKey), AESKEY_SIZE);
	std::string encryptedFileContent = aes.encrypt(
		reinterpret_cast<const char*>(filecon), filesize); // encrypt file content

	
	req.contentSize = encryptedFileContent.size();
	req.header.payloadSize = sizeof(req.contentSize) + NAME_SIZE + req.contentSize;
	req.message = new uint8_t[req.contentSize];
	memcpy(req.message, encryptedFileContent.c_str(), req.contentSize);

	uint8_t* buff = new uint8_t[req.header.payloadSize + sizeof(req.header)];
	uint8_t* ptr = buff;
	memcpy(ptr, &req, sizeof(req.header) + sizeof(req.contentSize) + NAME_SIZE);
	ptr += sizeof(req.header) + sizeof(req.contentSize) + NAME_SIZE;
	memcpy(ptr, req.message, req.contentSize);

	CRC c = CRC();
	uint32_t cksum = c.calcCrc(filePath);
	if (cksum == 0) {
		std::cerr << "Couldn't open file " << filePath << " for calculating CRC" << std::endl;
		delete[] buff;
		return false;
	}
	std::cout << "Cksum calculated: " << cksum << std::endl;
	size_t trys = 0;
	bool success = false;

	do {
		std::cout << "Attempt number " << trys + 1 << " of sending the encrypted file" << std::endl;
		size_t bytesLeft = filesize;

		if (!net.sendData(buff, req.header.payloadSize + sizeof(req.header))) {
			std::cerr << "Failed to send request to server" << std::endl;
			return false;
		}
		
		if (!net.receiveData(reinterpret_cast<uint8_t* const>(&res), sizeof(res))) {
			std::cerr << "Failed to receive response from server" << std::endl;
			return false;
		}

		if (!validateHeader(res.header, CODE_RES_FILE_CRC))
			return false;
		
		if (res.cksum == cksum) {
			success = true;
			reqCrc.header.code = CODE_REQ_CRC_VALID;
		}
		else {
			trys++;
			if(trys == 3)
				reqCrc.header.code = CODE_REQ_CRC_FAIL;
			else
				reqCrc.header.code = CODE_REQ_CRC_RETRY;
			std::cout << "Incorrect checksum received from server, "
				<< "trying to send the file again" << std::endl;
		}

		if (!net.sendData(reinterpret_cast<const uint8_t* const>(&reqCrc), sizeof(reqCrc))) {
			std::cerr << "Failed to send request to server" << std::endl;
			return false;
		}
		ResponseHeader resHeader = ResponseHeader();
		if (!net.receiveData(reinterpret_cast<uint8_t* const>(&resHeader), sizeof(resHeader))) {
			std::cerr << "Failed to receive response from server" << std::endl;
			return false;
		}
		if (!validateHeader(resHeader, CODE_RES_MESSAGE))
			return false;


	} while (trys < 3 && !success);

	if (success) 
		std::cout << "File " << filename << " was successfully stored in the server" << std::endl;
	else 
		std::cerr << "Attmpted to send the file 3 times unsuccessfully, aborting" << std::endl;

	delete[] buff;
	file.close();
	return true;
}