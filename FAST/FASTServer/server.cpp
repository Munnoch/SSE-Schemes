#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <cryptlib.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "hex.h"
#include <bitset>
#include <iostream>
#include "FASTServer.h"
#include <chrono>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 192
#define DEFAULT_PORT "27015"

using CryptoPP::byte;
using namespace CryptoPP;
using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::duration;
using std::chrono::milliseconds;

void printC(byte p) {
    std::bitset<8> x(p);
    std::cout << x << " ";
}

int __cdecl main(void)
{
    FASTServer testServer;
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult;
    const char* sendbuf;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    printf("Get Address\n");
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    printf("Get Socket\n");
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    printf("Get TCP\n");
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    printf("Get Client\n");
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    bool update = false;
    bool search = false;
    std::array<double, 1000> time;
    int count = 0;
    printf("Get Receive\n");
    do {

        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        //printf(recvbuf);
        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);
            if (recvbuf[0] == 'U') {
                printf("Update\n");
                update = true;
                search = false;
            }
            else if (recvbuf[0] == 'S') {
                printf("Search\n");
                update = false;
                search = true;
            }
            else if (update) {
                //auto t1 = high_resolution_clock::now();
                std::string encoded = recvbuf;
                std::string decoded;
                StringSource ss(encoded, true, new HexDecoder(new StringSink(decoded)));
                const byte* result = (const byte*)decoded.data();
                std::array<byte, 96> c;
                for (int a = 0; a < 96; a++) {
                    c[a] = result[a];
                }
                testServer.Update(c);
                //auto t2 = high_resolution_clock::now();
                //duration<double, std::milli> ms_double = t2 - t1;
                //time[count] = ms_double.count();
                //count++;
            }
            else if (search) {
                std::string encoded = recvbuf;
                std::string decoded;
                StringSource ss(encoded, true, new HexDecoder(new StringSink(decoded)));
                const byte* result = (const byte*)decoded.data();
                std::array<byte, 51> c;
                for (int a = 0; a < 51; a++) {
                    c[a] = result[a];
                }
                auto t1 = high_resolution_clock::now();
                std::set<std::array<byte, 45>> s = testServer.Search(c);
                auto t2 = high_resolution_clock::now();
                duration<double, std::milli> ms_double = t2 - t1;
                time[count] = ms_double.count();
                count++;
                std::set<std::array<byte, 45>>::iterator itr;
                for (itr = s.begin(); itr != s.end(); itr++) {
                    std::array<byte, 45> r = *itr;
                    byte o[45];
                    for (int a = 0; a < 45; a++) {
                        o[a] = r[a];
                    }
                    HexEncoder encoder;
                    std::string output;
                    encoder.Attach(new StringSink(output));
                    encoder.Put(o, sizeof(o));
                    encoder.MessageEnd();
                    sendbuf = output.c_str();
                    iSendResult = send(ClientSocket, sendbuf, iResult, 0);
                    if (iSendResult == SOCKET_ERROR) {
                        printf("send failed with error: %d\n", WSAGetLastError());
                        closesocket(ClientSocket);
                        WSACleanup();
                        return 1;
                    }
                    printf("Bytes sent: %d\n", iSendResult);
                }
            }
        }
        else if (iResult == 0) {

            for (int a = 0; a < count; a++) {
                std::cout << time[a] << std::endl;
            }

            printf("Connection closing...\n");
        }
        else {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}