#include "FileHandler.h"

bool FileHandler::fileExists(const std::string& path) {

	try {
		std::ifstream fs(path);
		return !fs.fail();
	}
	catch (std::exception&) {
		return false;
	}
}

bool FileHandler::openFile(std::fstream& file, const std::string& path, bool write) {

	try {
		if (write)
			file.open(path, std::fstream::out | std::fstream::binary);
		else
			file.open(path, std::fstream::in | std::fstream::binary);
		return file.is_open();
	}
	catch (std::exception&) {
		return false;
	}

}

bool FileHandler::writeToFile(std::fstream& file, const uint8_t* payload,
	const uint32_t bytes) {

	try {
		file.write(reinterpret_cast<const char*>(payload), bytes);
	}
	catch (std::exception&) {
		return false;
	}

	return true;
}

bool FileHandler::writeHex(std::fstream& file, const unsigned char* buffer, unsigned int length) {

	try {
		std::ios::fmtflags f(file.flags());
		file << std::hex;
		for (size_t i = 0; i < length; i++)
			file << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
		file << std::endl;
		file.flags(f);
	}
	catch (std::exception&) {
		return false;
	}
	return true;
}


size_t FileHandler::readFromFile(std::fstream& file, uint8_t* buff, uint32_t bytes) {

	try {
		file.read(reinterpret_cast<char*>(buff), bytes);
		std::streamsize bytes = file.gcount();
		return static_cast<size_t>(bytes);;
	}
	catch (std::exception&) {
		return 0;
	}
}

bool FileHandler::readLine(std::fstream& file, std::string& line) {
	try {
		if (!std::getline(file, line) || line.empty())
			return false;
		return true;
	}
	catch (std::exception&) {
		return false;
	}
}

std::string FileHandler::extractFileName(std::string path) {
	
	size_t fileNamePos = path.find_last_of('\\');
	if (fileNamePos == std::string::npos)
		return path;
	return path.substr(fileNamePos + 1);

}