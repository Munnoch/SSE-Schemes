#include <iostream>
#include <cryptlib.h>
#include <algorithm>
#include <bitset>
#include "osrng.h"
#include <set>
#include "SophosClient.h"
#include "SophosServer.h"
#include <cassert>
#include <boost/multiprecision/cpp_int.hpp>
#include <chrono>

using namespace boost::multiprecision;
using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;

void UpdateMain(SophosClient& testClient, SophosServer& testServer, const char* keyword, byte ind[64]) {
	array<byte, 96> c = testClient.Update(keyword, ind);
	testServer.Update(c);
}

void SearchMain(SophosClient& testClient, SophosServer& testServer, const char* keyword) {
	array<byte, 99> s = testClient.Search(keyword);
	bool check = false;
	for (int a = 0; a < 99; a++) {
		if (s[a] != 0x00) {
			check = true;
			break;
		}
	}
	if (!check) {
		cout << "Search not found" << endl;
	}
	else {
		//cout << "Found keyword" << endl;
		set<array<byte, 64>> results = testServer.Search(s);
		/*
		set<array<byte, 64>>::iterator itr;
		for (itr = results.begin(); itr != results.end(); itr++) {
			array<byte, 64> r = *itr;
			for (int a = 0; a < 64; a++) {
				std::bitset<8> x(r[a]);
				cout << x << " ";
			}
			cout << endl;
			cout << endl;
		}
		*/
	}
}

int512_t mul_inv(int512_t a, int512_t b)
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

int512_t modulo(int512_t a, int512_t b, int512_t n) {
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
/*
void hexString(char str[], int length) {
	char hexChar[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	int i;
	for (i = 0; i < length; i++) {
		str[i] = hexChar[rand() % 16];
	}
	str[length] = 0;
}

int main() {
	//rsa();
	SophosClient testClient;
	int512_t n = testClient.getN();
	SophosServer testServer;
	testServer.setVal(n);
	array<const char*, 32> sa = { "aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee" };
	const char* keyword = "Help";
	byte ind[64];
	AutoSeededRandomPool rng;
	int addSize = 10;
	for (int b = 0; b < 5; b++) {
		keyword = sa[b];
		//cout << b << endl;
		auto t1 = high_resolution_clock::now();
		for (int a = 0; a < addSize; a++) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind);
		}
		auto t2 = high_resolution_clock::now();
		duration<double, std::milli> ms_double = t2 - t1;
		cout << ms_double.count() << endl;
		addSize = addSize * 10;
	}
	addSize = 1000;
	//1289
	//13889
	for (int b = 0; b < 13889; b++) {
		char hex[10];
		hexString(hex, 10);
		keyword = hex;
		cout << b << endl;
		for (int a = 0; a < addSize; a++) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind);
		}
	}
	
	for (int c = 0; c < 5; c++) {
		for (int a = 0; a < 5; a++) {
			keyword = sa[a];
			auto t1 = high_resolution_clock::now();
			SearchMain(testClient, testServer, keyword);
			auto t2 = high_resolution_clock::now();
			duration<double, std::milli> ms_double = t2 - t1;
			cout << ms_double.count() << endl;
		}
	}
	int prob = 1;
	int size = 10000;
	keyword = "test1";
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind);
		}
		else {
			auto t1 = high_resolution_clock::now();
			SearchMain(testClient, testServer, keyword);
			auto t2 = high_resolution_clock::now();
			duration<double, std::milli> ms_double = t2 - t1;
			cout << p << "," << ms_double.count() << endl;
		}
	}
	prob = 10;
	keyword = "test2";
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind);
		}
		else {
			auto t1 = high_resolution_clock::now();
			SearchMain(testClient, testServer, keyword);
			auto t2 = high_resolution_clock::now();
			duration<double, std::milli> ms_double = t2 - t1;
			cout << p << "," << ms_double.count() << endl;
		}
	}
	prob = 100;
	keyword = "test3";
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind);
		}
		else {
			auto t1 = high_resolution_clock::now();
			SearchMain(testClient, testServer, keyword);
			auto t2 = high_resolution_clock::now();
			duration<double, std::milli> ms_double = t2 - t1;
			cout << p << "," << ms_double.count() << endl;
		}
	}
}

*/