#include "SophosClient.h"
#include <cryptlib.h>
#include "sha.h"
#include "osrng.h"
#include <array>
#include <bitset>
#include <iostream>
#include "aes.h"
#include "ccm.h"
#include "rsa.h"
#include <hex.h>
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;

int512_t SophosClient::mul_inv(int512_t a, int512_t b)
{
    int512_t b0 = b, t, q;
    int512_t x0 = 0, x1 = 1;
    if (b == 1) return 1;
    while (a > 1) {
        q = a / b;
        t = b, b = a % b, a = t;
        t = x0, x0 = x1 - q * x0, x1 = t;
    }
    if (x1 < 0) x1 += b0;
    return x1;
}

int512_t SophosClient::modulo(int512_t a, int512_t b, int512_t n) {
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

SophosClient::SophosClient() {
    AutoSeededRandomPool rngKey;
    rngKey.GenerateBlock(keyDefault, sizeof(keyDefault));
    m = {};
    AutoSeededRandomPool rng;
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 512);
    Integer pr = parameters.GetPrime1();
    Integer qr = parameters.GetPrime2();
    int512_t p1;
    byte pa[32];
    pr.Encode(pa, 32);
    int ex = 8 * 31;
    for (int a = 0; a < 32; a++) {
        int512_t temp = pa[a];
        int512_t p = (int512_t)pow(2, ex);
        p = p * temp;
        p1 += p;
        ex -= 8;
    }
    int512_t p2;
    byte qa[32];
    qr.Encode(qa, 32);
    ex = 8 * 31;
    for (int a = 0; a < 32; a++) {
        int512_t temp = qa[a];
        int512_t p = (int512_t)pow(2, ex);
        p = p * temp;
        p2 += p;
        ex -= 8;
    }
    n = p1 * p2;
    int512_t phiN = (p1 - 1) * (p2 - 1);
    e = 65537;
    d = mul_inv(e, phiN);
}

array<byte, 96> SophosClient::Update(const char* keyword, byte ind[64]) {
    AutoSeededRandomPool rng;
    SHA256 hash;
    SHA512 hash64;
    byte digest[SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*)keyword, 32);
    ECB_Mode<AES>::Encryption aes1(keyDefault, AES::DEFAULT_KEYLENGTH); 
    byte output[32];
    aes1.ProcessData(output, digest, SHA256::DIGESTSIZE);
    int stateSize;
    if (m.find(keyword) == m.end()) {
        stateSize = 0;
    }
    else {
        stateSize = m.at(keyword).size();
    }
    byte state[64];
    int size = 64;
    if (stateSize == 0) {
        rng.GenerateBlock(state, sizeof(state));
        int bit = state[0];
        if (bit > 128) {
            bit -= 128;
            state[0] = bit;
        }
        map<int, byte[64]> stateMap;
        for (int a = 0; a < size; a++) {
            stateMap[stateSize][a] = state[a];
        }
        m.insert(make_pair(keyword, stateMap));
    }
    else {
        for (int a = 0; a < size; a++) {
            state[a] = m.at(keyword)[stateSize - 1][a];
        }
        int512_t x = 0;
        int ex = 8 * (sizeof(state) - 1);
        for (int a = 0; a < sizeof(state); a++) {
            int512_t temp = state[a];
            int512_t p = (int512_t)pow(2, ex);
            p = p * temp;
            x += p;
            ex -= 8;
        }
        int512_t y = modulo(x, d, n);
        int temp = 8 * 63;
        for (int a = 0; a < 63; a++) {
            state[a] = (byte)(y >> temp) & 0xFF;
            temp -= 8;
        }
        state[63] = (byte)y & 0xff;
        for (int a = 0; a < size; a++) {
            m.at(keyword)[stateSize][a] = state[a];
        }
    }
    byte u[96];
    for (int a = 0; a < 32; a++) {
        u[a] = output[a];
    }
    for (int a = 32; a < 96; a++) {
        u[a] = state[a - 32];
    }
    byte ut[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(ut, u, 96);
    byte ud[CryptoPP::SHA512::DIGESTSIZE];
    hash64.CalculateDigest(ud, u, 96);
    byte e[64];
    for (int a = 0; a < 64; a++) {
        e[a] = ind[a] ^ ud[a];
    }
    array<byte, 96> c;
    for (int a = 0; a < 32; a++) {
        c[a] = ut[a];
    }
    for (int a = 32; a < 96; a++) {
        c[a] = e[a - 32];
    }
    return c;
}

array<byte, 99> SophosClient::Search(const char* keyword) {
    SHA256 hash;
    byte digest[SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (byte*)keyword, 32);
    ECB_Mode<AES>::Encryption aes1(keyDefault, AES::DEFAULT_KEYLENGTH);
    byte output[32];
    aes1.ProcessData(output, digest, SHA256::DIGESTSIZE);
    int stateSize;
    byte state[64];
    if (m.find(keyword) == m.end()) {
        array<byte, 99> c{};
        return c;
    }
    else {
        stateSize = m.at(keyword).size();
        for (int a = 0; a < 64; a++) {
            state[a] = m.at(keyword)[stateSize - 1][a];
        }
    }
    array<byte, 99> c;
    for (int a = 0; a < 32; a++) {
        c[a] = output[a];
    }
    for (int a = 32; a < 96; a++) {
        c[a] = state[a - 32];
    }
    c[96] = 0;
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
        c[96] = temp;
    }
    c[97] = 0;
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
        c[97] = temp;
    }
    c[98] = stateSize;
    return c;
}

int512_t SophosClient::getN() {
    return n;
}

void SophosClient::printC(byte p) {
    std::bitset<8> x(p);
    cout << x << " ";
}