#include "SophosServer.h"
#include <cryptlib.h>
#include "sha.h"
#include "osrng.h"
#include "hex.h"
#include <array>
#include <bitset>
#include <iostream>
#include "aes.h"
#include "ccm.h"
#include "rsa.h"
#include <set>
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

int512_t SophosServer::modulo(int512_t a, int512_t b, int512_t n) {
	int1024_t x = 1, y = a;
	while (b > 0) {
		if (b % 2 == 1) {
			x = (x * y) % n; // multiplying with base
		}
		y = (y * y) % n; // squaring the base
		b /= 2;
	}
	return (int512_t)x % n;
}

SophosServer::SophosServer() {
	m = {};
	ebig = 65537;
}

void SophosServer::Update(array<byte, 96> c) {
	byte u[32];
	array<unsigned char, 32> ch;
	for (int a = 0; a < 32; a++) {
		u[a] = c[a];
		ch[a] = u[a];
	}
	byte e[64];
	for (int a = 32; a < 96; a++) {
		e[a - 32] = c[a];
	}
	for (int a = 0; a < 64; a++) {
		m[ch][a] = e[a];
	}
}

set<array<byte, 64>> SophosServer::Search(array<byte, 99> s) {
	SHA256 hash;
	SHA512 hash64;
	AutoSeededRandomPool rng;
	set<array<byte, 64>> ID;
	byte kw[32];
	for (int a = 0; a < 32; a++) {
		kw[a] = s[a];
	}
	byte state[64];
	for (int a = 32; a < 96; a++) {
		state[a - 32] = s[a];
	}
	int stateSize = s[98];
	stateSize += s[97] * 256;
	stateSize += s[96] * 65536;
	byte u[96];
	for (int a = 0; a < 32; a++) {
		u[a] = kw[a];
	}
	for (int i = stateSize; i > 0; i--) {
		for (int a = 32; a < 96; a++) {
			u[a] = state[a - 32];
		}
		byte ut[CryptoPP::SHA256::DIGESTSIZE];
		hash.CalculateDigest(ut, u, 96);
		array<unsigned char, 32> ch;
		for (int l = 0; l < 32; l++) {
			ch[l] = ut[l];
		}
		byte e[64];
		for (int a = 0; a < 64; a++) {
			e[a] = m[ch][a];
		}
		byte ud[CryptoPP::SHA512::DIGESTSIZE];
		hash64.CalculateDigest(ud, u, 96);
		array<byte, 64> ind;
		for (int a = 0; a < 64; a++) {
			ind[a] = e[a] ^ ud[a];
		}
		ID.insert(ind);
		int512_t x = 0;
		int ex = 8 * (sizeof(state) - 1);
		for (int a = 0; a < sizeof(state); a++) {
			int512_t temp = state[a];
			int512_t p = (int512_t)pow(2, ex);
			p = p * temp;
			x += p;
			ex -= 8;
		}
		int512_t y = modulo(x, ebig, n);
		int temp = 8 * 63;
		for (int a = 0; a < 63; a++) {
			state[a] = (byte)(y >> temp) & 0xFF;
			temp -= 8;
		}
		state[63] = (byte)y & 0xff;
	}
	return ID;
}


void SophosServer::printC(byte p) {
	std::bitset<8> x(p);
	cout << x << " ";
}

void SophosServer::setVal(int512_t nin) {
	n = nin;
}