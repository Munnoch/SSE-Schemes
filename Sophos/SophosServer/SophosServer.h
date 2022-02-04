#include <cryptlib.h>
#include <array>
#include <set>
#include "rsa.h"
#include <boost/multiprecision/cpp_int.hpp>
#pragma once

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;

class SophosServer
{
public:
	SophosServer();
	void Update(std::array<byte, 96> c);
	std::set<std::array<byte, 64>> Search(std::array<byte, 99> s);
	void printC(byte c);
	void setVal(int512_t n);
	int512_t modulo(int512_t a, int512_t b, int512_t n);
protected:
	int512_t n;
	int512_t ebig;
	std::map<std::array<unsigned char, 32>, byte[64]> m;
};

