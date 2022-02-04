#include <cryptlib.h>
#include <array>
#include <set>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class FASTServer
{
public:
	FASTServer();
	void Update(array<byte, 96> c);
	set<array<byte, 45>> Search(array<byte, 51> s);
	void printB(byte p);
protected:
	map<array<unsigned char, 32>, byte[64]> m;
	byte add[3];
	byte del[3];
};

