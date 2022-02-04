#include <cryptlib.h>
#include <array>
#include "rsa.h"
#include <boost/multiprecision/cpp_int.hpp>
#pragma once

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class SophosClient
{
public: 
	SophosClient();
	array<byte, 96> Update(const char* keyword, byte ind[64]);
	array<byte, 99> Search(const char* keyword);
	int512_t getN();
	void printC(byte c);
	int512_t mul_inv(int512_t a, int512_t b);
	int512_t modulo(int512_t a, int512_t b, int512_t n);
protected:
	byte keyDefault[16];
	map <const char*, map<int, byte[64]>> m;
	int512_t n;
	int512_t e;
	int512_t d;
};

