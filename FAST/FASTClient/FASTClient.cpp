#include "sha.h"
#include "hex.h"
#include "aes.h"
#include "ccm.h"
#include "modes.h"
#include "filters.h"
#include "osrng.h"
#include <cryptlib.h>
#include <iostream>
#include <random>
#include <bitset>
#include <array>
#include "FASTClient.h"
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

FASTClient::FASTClient() {
    AutoSeededRandomPool rngKey;
    rngKey.GenerateBlock(keyDefault, sizeof(keyDefault));
    m = {};
}

array<byte, 96> FASTClient::Update(const char* keyword, byte ind[45], byte op[3]) {
    AutoSeededRandomPool rng;
    SHA256 hash;
    SHA512 hash64;
    byte digest[SHA256::DIGESTSIZE]; 
    hash.CalculateDigest(digest, (byte*)keyword, 32); 
    ECB_Mode<AES>::Encryption aes1(keyDefault, AES::DEFAULT_KEYLENGTH); 
    byte output[32];
    aes1.ProcessData(output, digest, SHA256::DIGESTSIZE);
    map<int, byte[16]> stateMap;
    int stateSize;
    if (m.find(keyword) == m.end()) {
        stateSize = 0;
    }
    else {
        stateSize = m.at(keyword).size();
    }
    byte state[16];
    if (stateSize == 0) {
        rng.GenerateBlock(state, sizeof(state));
        for (int a = 0; a < 16; a++) {
            stateMap[stateSize][a] = state[a];
        }
        m.insert(make_pair(keyword, stateMap));
        stateSize++;
    }
    else {
        for (int a = 0; a < 16; a++) {
            state[a] = m.at(keyword)[stateSize - 1][a];
        }
    }
    byte nextKey[CryptoPP::AES::DEFAULT_KEYLENGTH]; 
    rng.GenerateBlock(nextKey, sizeof(nextKey));
    ECB_Mode<AES>::Encryption aes2(nextKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
    byte newState[16];
    aes2.ProcessData(newState, state, AES::DEFAULT_KEYLENGTH);
    for (int a = 0; a < 16; a++) {
        m.at(keyword)[stateSize][a] = newState[a];
    }
    byte e1[64];
    for (int a = 0; a < 45; a++) {
        e1[a] = ind[a];
    }
    for (int a = 45; a < 48; a++) {
        e1[a] = op[a - 45];
    }
    for (int a = 48; a < 64; a++) {
        e1[a] = nextKey[a - 48];
    }
    byte e2[48];
    for (int a = 0; a < 32; a++) {
        e2[a] = output[a];
    }
    for (int a = 32; a < 48; a++) {
        e2[a] = newState[a - 32];
    }
    byte ed[CryptoPP::SHA512::DIGESTSIZE]; 
    hash64.CalculateDigest(ed, e2, 48);
    byte e[64];
    for (int a = 0; a < 64; a++) {
        e[a] = e1[a] ^ ed[a];
    }
    byte u[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(u, e2, 48);
    array<byte, 96> c;
    for (int a = 0; a < 32; a++) {
        c[a] = u[a];
    }
    for (int a = 32; a < 96; a++) {
        c[a] = e[a - 32];
    }
    return c;
}

array<byte, 51> FASTClient::Search(const char* keyword) {
    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE]; 
    hash.CalculateDigest(digest, (byte*)keyword, 32); 
    ECB_Mode<AES>::Encryption aes1(keyDefault, AES::DEFAULT_KEYLENGTH); 
    byte output[32];
    aes1.ProcessData(output, digest, SHA256::DIGESTSIZE);
    int stateIndex;
    byte state[16];
    if (m.find(keyword) == m.end()) {
        array<byte, 51> c{};
        return c;
    }
    else {
        stateIndex = m.at(keyword).size() - 1;
        for (int a = 0; a < 16; a++) {
            state[a] = m.at(keyword)[stateIndex][a];
        }
    }
    array<byte, 51> c;
    for (int a = 0; a < 32; a++) {
        c[a] = output[a];
    }
    for (int a = 32; a < 48; a++) {
        c[a] = state[a - 32];
    }
    c[48] = 0;
    if (stateIndex >= 65536) {
        int temp = 0;
        int ad = 128;
        int m = 65536 * ad;
        for (int b = 0; b < 8; b++) {
            if (stateIndex > m) {
                temp += ad;
                stateIndex -= m;
            }
            ad /= 2;
            m = 65536 * ad;
        }
        c[48] = temp;
    }
    c[49] = 0;
    if (stateIndex >= 256) {
        int temp = 0;
        int ad = 128;
        int m = 256 * ad;
        for (int b = 0; b < 8; b++) {
            if (stateIndex > m) {
                temp += ad;
                stateIndex -= m;
            }
            ad /= 2;
            m = 256 * ad;
        }
        c[49] = temp;
    }
    c[50] = stateIndex;
    return c;
}

void FASTClient::print(byte b[], int s, int e) {
    for (int j = s; j < e; j++) {
        printC(b[j]);
    }
    cout << endl;
}

void FASTClient::printC(byte p) {
    std::bitset<8> x(p);
    cout << x << " ";
}

void FASTClient::printA(array<byte, 64> a) {
    for (int j = 0; j < 64; j++) {
        printC(a[j]);
    }
    cout << endl;
}

void FASTClient::printS(array<byte, 49> a) {
    for (int j = 0; j < 64; j++) {
        printC(a[j]);
    }
    cout << endl;
}

void FASTClient::mapSize() {
    cout << m.size() << endl;
}
