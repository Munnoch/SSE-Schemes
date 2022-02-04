#include <cryptlib.h>
#include <array>
#pragma once

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class FASTClient
{
public:
	FASTClient();
	array<byte, 96> Update(const char* keyword, byte ind[45], byte op[3]);
	array<byte, 51> Search(const char* keyword);
	void print(byte b[], int s, int e);
	void printC(byte c);
	void printA(array<byte, 64> a);
	void printS(array<byte, 49> a);
	void mapSize();
protected:
	map <const char*, map<int, byte[16]>> m;
	byte keyDefault[16];
};

