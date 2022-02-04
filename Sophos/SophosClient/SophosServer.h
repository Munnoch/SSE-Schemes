#include <cryptlib.h>
#include <array>
#include <set>
#include "rsa.h"
#include <boost/multiprecision/cpp_int.hpp>
#pragma once

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

class SophosServer
{
public:
	SophosServer();
	void Update(array<byte, 96> c);
	set<array<byte, 64>> Search(array<byte, 99> s);
	void printC(byte c);
	void setVal(int512_t n);
	int512_t modulo(int512_t a, int512_t b, int512_t n);
protected:
	int512_t n;
	int512_t ebig;
	map<array<unsigned char, 32>, byte[64]> m;
};

