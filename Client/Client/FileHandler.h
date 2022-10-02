#pragma once
#include <string>
#include <fstream>
#include <iomanip>

class FileHandler
{
public:
	bool fileExists(const std::string&);
	bool openFile(std::fstream&, const std::string&, bool);
	bool writeToFile(std::fstream&, const uint8_t*, const uint32_t);
	bool readFromFile(std::fstream&, uint8_t*, uint32_t);
	bool readLine(std::fstream&, std::string&);
	bool writeHex(std::fstream&, const unsigned char*, unsigned int);
};

