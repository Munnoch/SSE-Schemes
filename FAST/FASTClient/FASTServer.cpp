#include <cryptlib.h>
#include "sha.h"
#include "filters.h"
#include "hex.h"
#include "aes.h"
#include "ccm.h"
#include <set>
#include <iostream>
#include <bitset>
#include "FASTServer.h"
#include <chrono>

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;

FASTServer::FASTServer() {
	m = {};
	add[0] = 0x61;
	add[1] = 0x64;
	add[2] = 0x64;
	del[0] = 0x64;
	del[1] = 0x65;
	del[2] = 0x6c;
}

void FASTServer::Update(array<byte, 96> c) {
	byte u[32];
	for (int a = 0; a < 32; a++) {
		u[a] = c[a];
	}
	byte e[64];
	for (int a = 32; a < 96; a++) {
		e[a - 32] = c[a];
	}
	array<unsigned char, 32> ch;
	for (int l = 0; l < 32; l++) {
		ch[l] = u[l];
	}
	for (int a = 0; a < 64; a++) {
		m[ch][a] = e[a];
	}
}

set<array<byte, 45>> FASTServer::Search(array<byte, 51> s) {
	SHA256 hash;
	SHA512 hash64;
	byte state[16];
	for (int a = 32; a < 48; a++) {
		state[a - 32] = s[a];
	}
	int index = s[50];
	index += s[49] * 256;
	index += s[48] * 65536;
	set<array<byte, 45>> deleted;
	set<array<byte, 45>> ID;
	byte current[48];
	for (int a = 0; a < 32; a++) {
		current[a] = s[a];
	}
	byte u[SHA256::DIGESTSIZE];
	array<unsigned char, 32> ch;
	byte r[SHA512::DIGESTSIZE];
	array<byte, 45> ind;
	byte op[3];
	byte key[16];
	bool check = false;
	byte newState[AES::DEFAULT_KEYLENGTH];
	for (int j = index - 1; j >= 0; j--) {
		for (int a = 32; a < 48; a++) {
			current[a] = state[a - 32];
		}
		hash.CalculateDigest(u, current, 48);
		for (int l = 0; l < 32; l++) {
			ch[l] = u[l];
		}
		hash64.CalculateDigest(r, current, 48);
		for (int a = 0; a < 45; a++) {
			ind[a] = r[a] ^ m[ch][a];
		}
		for (int a = 45; a < 48; a++) {
			op[a - 45] = r[a] ^ m[ch][a];
		}
		for (int a = 48; a < 64; a++) {
			key[a - 48] = r[a] ^ m[ch][a];
		}
		if (op[0] == del[0] && op[1] == del[1] && op[2] == del[2]) {
			deleted.insert(ind);
		}
		else if (op[0] == add[0] && op[1] == add[1] && op[2] == add[2]) {
			set<array<byte, 45>>::iterator itr;
			check = false;
			for (itr = deleted.begin(); itr != deleted.end(); itr++) {
				if (*itr == ind) {
					deleted.erase(ind);
					check = true;
					break;
				}
			}
			if (!check) {
				ID.insert(ind);
			}
		}
		ECB_Mode<AES>::Decryption aes1(key, AES::DEFAULT_KEYLENGTH);
		aes1.ProcessData(state, state, 16);
	}
	return ID;
}

void FASTServer::printB(byte p) {
	std::bitset<8> x(p);
	cout << x << endl;
}