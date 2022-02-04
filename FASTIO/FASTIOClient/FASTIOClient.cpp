#include "FASTIOClient.h"
#include <cryptlib.h>
#include "sha.h"
#include "osrng.h"
#include <array>
#include <bitset>
#include <iostream>
#include "aes.h"
#include "ccm.h"

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

FASTIOClient::FASTIOClient() {
    AutoSeededRandomPool rngKey;
    rngKey.GenerateBlock(keyDefault, sizeof(keyDefault));
    m = {};
}

array<byte, 96> FASTIOClient::Update(const char* keyword, byte ind[61], byte op[3]) {
    AutoSeededRandomPool rng;
    SHA256 hash;
    SHA512 hash64;
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
    byte u1[19];
    for (int a = 0; a < 16; a++) {
        u1[a] = state[a];
    }
    u1[16] = 0;
    int t = stateSize;
    if (t >= 65536) {
        int temp = 0;
        int ad = 128;
        int m = 65536 * ad;
        for (int b = 0; b < 8; b++) {
            if (t > m) {
                temp += ad;
                t -= m;
            }
            ad /= 2;
            m = 65536 * ad;
        }
        u1[16] = temp;
    }
    u1[17] = 0;
    if (t >= 256) {
        int temp = 0;
        int ad = 128;
        int m = 256 * ad;
        for (int b = 0; b < 8; b++) {
            if (t > m) {
                temp += ad;
                t -= m;
            }
            ad /= 2;
            m = 256 * ad;
        }
        u1[17] = temp;
    }
    u1[18] = t;
    byte u[SHA256::DIGESTSIZE]; 
    hash.CalculateDigest(u, u1, 19);
    byte e1[64];
    for (int a = 0; a < 61; a++) {
        e1[a] = ind[a];
    }
    for (int a = 61; a < 64; a++) {
        e1[a] = op[a - 61];
    }
    byte eh[SHA512::DIGESTSIZE];
    hash64.CalculateDigest(eh, u1, 17);
    byte e[64];
    for (int a = 0; a < 64; a++) {
        e[a] = e1[a] ^ eh[a];
    }
    for (int a = 0; a < 16; a++) {
        m.at(keyword)[stateSize][a] = state[a];
    }
    array<byte, 96> c;
    for (int a = 0; a < 32; a++) {
        c[a] = u[a];
    }
    for (int a = 32; a < 96; a++) {
        c[a] = e[a - 32];
    }
    return c;
}

array<byte, 51> FASTIOClient::Search(const char* keyword) {
    AutoSeededRandomPool rng;
    SHA256 hash;
    int stateSize;
    byte state[16];
    if (m.find(keyword) == m.end()) {
        array<byte, 51> c{};
        return c;
    }
    else {
        stateSize = m.at(keyword).size();
        for (int a = 0; a < 16; a++) {
            state[a] = m.at(keyword)[stateSize - 1][a];
        }
    }
    byte digest[SHA256::DIGESTSIZE]; 
    hash.CalculateDigest(digest, (byte*)keyword, 32); 
    ECB_Mode<AES>::Encryption aes1(keyDefault, AES::DEFAULT_KEYLENGTH); 
    byte output[32];
    aes1.ProcessData(output, digest, SHA256::DIGESTSIZE);
    byte keyW[16] = {};
    if (stateSize - 1 != 0) {
        for (int a = 0; a < 16; a++) {
            keyW[a] = state[a];
        }
        rng.GenerateBlock(state, sizeof(state));
        map<int, byte[16]> newStateMap;
        for (int a = 0; a < 16; a++) {
            newStateMap[0][a] = state[a];
        }
        m[keyword] = newStateMap;
    }
    array<byte, 51> r;
    for (int a = 0; a < 32; a++) {
        r[a] = output[a];
    }
    for (int a = 32; a < 48; a++) {
        r[a] = keyW[a - 32];
    }
    r[48] = 0;
    stateSize--;
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
        r[48] = temp;
    }
    r[49] = 0;
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
        r[49] = temp;
    }
    r[50] = stateSize;
    return r;
}

void FASTIOClient::print(byte b[], int s, int e) {
    for (int j = s; j < e; j++) {
        printC(b[j]);
    }
    cout << endl;
}

void FASTIOClient::printC(byte p) {
    std::bitset<8> x(p);
    cout << x << " ";
}