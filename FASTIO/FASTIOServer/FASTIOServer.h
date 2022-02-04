#include <cryptlib.h>
#include <array>
#include <set>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;

class FASTIOServer
{
public:
	FASTIOServer();
	void Update(std::array<byte, 96> c);
	std::set<std::array<byte, 61>> Search(std::array<byte, 51> s);
	void print(byte b[], int s, int e);
	void printC(byte c);
protected:
	std::map<std::array<unsigned char, 32 > , byte[64]> mapIndex;
	std::map<std::array<byte, 32>, std::set<std::array<byte, 61>>> mapResults;
	byte add[3];
	byte del[3];
};
