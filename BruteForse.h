#pragma once

#include <iostream>
#include <sstream>
#include <stdio.h>
#include <math.h>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <map>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "FileStream.h"

#define MAX_SIZE 10         // only used to avoid errors
#define CHAR_COUNT 36       // size of the charset you want to use (number of possible chars for the password)
#define PASS_LENGTH 4
#define PASS_3_CHARS 46656
#define PASS_4_CHARS 1679616

class BruteForce
{
public:
	BruteForce(const std::string pathFile);
	void GenerateGuess(std::vector<std::string>& guessPassList, const size_t countGeneratePass = pow(CHAR_COUNT, PASS_LENGTH));

	std::vector<unsigned char> GetHashKey();
	std::vector<unsigned char> Get—ipherOnlyText();

private:

	std::vector<unsigned char> m_hashKey;
	std::vector<unsigned char> m_cipherOnlyText;// text without hash
	size_t m_countGuess = 0;
private:
	int m_guessCounter[MAX_SIZE] = { }; // counter
	char m_guess[MAX_SIZE + 1];         // chars crresponding to counter
	const unsigned char m_chars[CHAR_COUNT + 1] = "abcdefghijklmnopqrstuvwxyz0123456789";
};