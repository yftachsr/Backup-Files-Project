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

bool FileHandler::readFromFile(std::fstream& file, uint8_t* buff, uint32_t bytes) {

	try {
		file.read(reinterpret_cast<char*>(buff), bytes);
		return true;
	}
	catch (std::exception&) {
		return false;
	}
}