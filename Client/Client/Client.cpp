#include "Client.h"

Client::Client() {
	Networking net();
}

bool Client::start() {

	if (!parseTransferInfo())
		return false;
	if(!fileHandler.fileExists(INFO_FILE))
		registerRequest();

		
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

bool extractIPPort(std::string str, std::string& addr, std::string& port) {
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

	RegisterRequest req();
	RegisterResponse res();

	req.header.payloadsize = sizeof(req.name);
}