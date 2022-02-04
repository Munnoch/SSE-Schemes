#include <cryptlib.h>
#include <array>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class FASTIOClient
{
public:
	FASTIOClient();
	array<byte, 96> Update(const char* keyword, byte ind[61], byte op[3]);
	array<byte, 51> Search(const char* keyword);
	void print(byte b[], int s, int e);
	void printC(byte c);
protected:
	map <const char*, map<int, byte[16]>> m;
	byte keyDefault[16];
};

