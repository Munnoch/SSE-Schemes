#include <cryptlib.h>
#include <array>
#include <set>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;

class FASTServer
{
public:
	FASTServer();
	void Update(std::array<byte, 96> c);
	std::set<std::array<byte, 45>> Search(std::array<byte, 51> s);
	void printB(byte p);
protected:
	std::map<std::array<unsigned char, 32>, byte[64]> m;
	byte add[3];
	byte del[3];
};

