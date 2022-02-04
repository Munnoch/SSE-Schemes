#include "FASTIOClient.h"
#include "FASTIOServer.h"
#include <cryptlib.h>
#include <iostream>
#include <array>
#include "osrng.h"
#include <bitset>
#include <chrono>

using CryptoPP::byte;
using namespace CryptoPP;
using namespace std;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;

void UpdateMain(FASTIOClient& testClient, FASTIOServer& testServer, const char* keyword, byte ind[61], byte op[3]) {
	array<byte, 96> c = testClient.Update(keyword, ind, op);
	testServer.Update(c);
}

void SearchMain(FASTIOClient& testClient, FASTIOServer& testServer, const char* keyword) {
	array<byte, 51> s = testClient.Search(keyword);
	bool check = false;
	for (int a = 0; a < 51; a++) {
		if (s[a] != 0x00) {
			check = true;
			break;
		}
	}
	if (!check) {
		cout << "Search not found" << endl;
	}
	else {
		set<array<byte, 61>> results = testServer.Search(s);
		/*
		set<array<byte, 61>>::iterator itr;
		int count = 0;
		for (itr = results.begin(); itr != results.end(); itr++) {
			count++;

			array<byte, 61> r = *itr;
			for (int a = 0; a < 61; a++) {
				std::bitset<8> x(r[a]);
				cout << x << " ";
			}
			cout << endl;
			
		}
		cout << count << endl;
		*/
	}
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
	FASTIOClient testClient;
	FASTIOServer testServer;
	array<const char*, 32> sa1 = { "aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee" };
	array<const char*, 32> sa2 = { "fffff", "ggggg", "hhhhh", "iiiii", "jjjjj" };
	array<const char*, 32> sa3 = { "kkkkk", "lllll", "mmmmm", "nnnnn", "ooooo" };
	const char* keyword;
	byte add[3] = { 0x61, 0x64, 0x64 };
	byte del[3] = { 0x64, 0x65, 0x6c };
	byte ind[61];
	AutoSeededRandomPool rng;
	int addSize = 10;
	
	for (int b = 0; b < 5; b++) {
		keyword = sa1[b];
		//cout << b << endl;
		auto t1 = high_resolution_clock::now();
		for (int a = 0; a < addSize; a++) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind, add);
		}
		auto t2 = high_resolution_clock::now();
		duration<double, std::milli> ms_double = t2 - t1;
		cout << ms_double.count() << endl;
		addSize = addSize * 10;
	}
	
	addSize = 1000;
	// 1289
	// 13889
	// 139889
	for (int b = 0; b < 14000; b++) {
		char hex[10];
		hexString(hex, 10);
		keyword = hex;
		cout << b << endl;
		for (int a = 0; a < addSize; a++) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind, add);
		}
	}
	
	std::chrono::milliseconds timespan(10000);
	std::this_thread::sleep_for(timespan);
	for (int a = 0; a < 5; a++) {
		keyword = sa1[a];
		auto t1 = high_resolution_clock::now();
		SearchMain(testClient, testServer, keyword);
		auto t2 = high_resolution_clock::now();
		duration<double, std::milli> ms_double = t2 - t1;
		cout << ms_double.count() << endl;
	}
	for (int a = 0; a < 5; a++) {
		keyword = sa2[a];
		auto t1 = high_resolution_clock::now();
		SearchMain(testClient, testServer, keyword);
		auto t2 = high_resolution_clock::now();
		duration<double, std::milli> ms_double = t2 - t1;
		cout << ms_double.count() << endl;
	}
	for (int a = 0; a < 5; a++) {
		keyword = sa3[a];
		auto t1 = high_resolution_clock::now();
		SearchMain(testClient, testServer, keyword);
		auto t2 = high_resolution_clock::now();
		duration<double, std::milli> ms_double = t2 - t1;
		cout << ms_double.count() << endl;
	}
	
	int prob = 1;
	int size = 10000;
	keyword = "test1";
	cout << keyword << endl;
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind, add);
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
	cout << keyword << endl;
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind, add);
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
	cout << keyword << endl;
	for (int p = 0; p < 100000; p++) {
		int r = (rand() % size) + 1;
		if (r > prob) {
			rng.GenerateBlock(ind, sizeof(ind));
			UpdateMain(testClient, testServer, keyword, ind, add);
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