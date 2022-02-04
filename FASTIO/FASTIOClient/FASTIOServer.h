#include <cryptlib.h>
#include <array>
#include <set>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class FASTIOServer
{
public:
	FASTIOServer();
	void Update(array<byte, 96> c);
	set<array<byte, 61>> Search(array<byte, 51> s);
	void print(byte b[], int s, int e);
	void printC(byte c);
protected:
	map<array<unsigned char, 32>, byte[64]> mapIndex;
	map<array<byte, 32>, set<array<byte, 61>>> mapResults;
	byte add[3];
	byte del[3];
};

