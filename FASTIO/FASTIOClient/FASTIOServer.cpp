#include "FASTIOServer.h"
#include <cryptlib.h>
#include "sha.h"
#include "osrng.h"
#include <array>
#include <bitset>
#include <iostream>
#include "aes.h"
#include "ccm.h"
#include <set>
#include "hex.h"

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

FASTIOServer::FASTIOServer() {
	mapIndex = {};
	mapResults = {};
	add[0] = 0x61;
	add[1] = 0x64;
	add[2] = 0x64;
	del[0] = 0x64;
	del[1] = 0x65;
	del[2] = 0x6c;
}

void FASTIOServer::Update(array<byte, 96> c) {
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
		mapIndex[ch][a] = e[a];
	}
}

set<array<byte, 61>> FASTIOServer::Search(array<byte, 51> s) {
	array<byte, 32> tw;
	SHA256 hash;
	SHA512 hash64;
	for (int a = 0; a < 32; a++) {
		tw[a] = s[a];
	}
	byte keyW[16];
	for (int a = 32; a < 48; a++) {
		keyW[a - 32] = s[a];
	}
	int index = s[50];
	index += s[49] * 256;
	index += s[48] * 65536;
	set<array<byte, 61>> ID;
	if (mapResults.find(tw) != mapResults.end()) {
		ID = mapResults[tw];
	}
	bool check = false;
	for (int a = 0; a < 16; a++) {
		if (keyW[a] != 0x00) {
			check = true;
			break;
		}
	}
	if (!check) {
		return ID;
	}
	for (int i = 1; i <= index; i++) {
		byte uc[19];
		for (int a = 0; a < 16; a++) {
			uc[a] = keyW[a];
		}
		uc[16] = 0;
		int stateSize = i;
		if (stateSize >= 65536) {
			int temp = 0;
			int ad = 128;
			int m = 65536 * ad;
			for (int b = 0; b < 8; b++) {
				if (stateSize > m) {
					temp += ad;
					stateSize -= m;
				}
				ad /= 2;
				m = 65536 * ad;
			}
			uc[16] = temp;
		}
		uc[17] = 0;
		if (stateSize >= 256) {
			int temp = 0;
			int ad = 128;
			int m = 256 * ad;
			for (int b = 0; b < 8; b++) {
				if (stateSize > m) {
					temp += ad;
					stateSize -= m;
				}
				ad /= 2;
				m = 256 * ad;
			}
			uc[17] = temp;
		}
		uc[18] = stateSize;
		byte ui[SHA256::DIGESTSIZE];
		hash.CalculateDigest(ui, uc, 19);
		byte eh[SHA512::DIGESTSIZE];
		hash64.CalculateDigest(eh, uc, 19);
		array<unsigned char, 32> ch;
		for (int l = 0; l < 32; l++) {
			ch[l] = ui[l];
		}
		array<byte, 61> ind;
		for (int a = 0; a < 61; a++) {
			ind[a] = eh[a] ^ mapIndex[ch][a];
		}
		byte op[3];
		for (int a = 61; a < 64; a++) {
			op[a - 61] = eh[a] ^ mapIndex[ch][a];
		}
		if (op[0] == del[0] && op[1] == del[1] && op[2] == del[2]) {
			ID.erase(ind);
		}
		else if (op[0] == add[0] && op[1] == add[1] && op[2] == add[2]) {
			ID.insert(ind);
		}
		mapIndex.erase(ch);
	}
	mapResults[tw] = ID;
	return ID;
}

void FASTIOServer::print(byte b[], int s, int e) {
	for (int j = s; j < e; j++) {
		printC(b[j]);
	}
	cout << endl;
}

void FASTIOServer::printC(byte p) {
	std::bitset<8> x(p);
	cout << x << " ";
}
