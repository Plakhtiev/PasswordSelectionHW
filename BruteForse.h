#pragma once

#include <iostream>
#include <stdio.h>
#include <math.h>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>

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
	void GetGuess(const size_t countGeneratePass = pow(CHAR_COUNT, PASS_LENGTH));
	std::string GetFoundPass();
	void SetFoundPass(std::string pass);
	void SetCountChekedPass(size_t count);
	size_t GetCountChekedPass();
	std::vector<std::string> GetGeneratedPass();
	std::vector<std::string> GetGeneratedPass(size_t beginIndex);
	std::vector<unsigned char> GetHashKey();
	std::vector<unsigned char> Get—ipherOnlyText();
	
private:
	std::vector<std::string> m_guessPassList;
	std::vector<unsigned char> m_hashKey;
	std::vector<unsigned char> m_cipherOnlyText;// text without hash
	size_t m_countGuess = 0;
	size_t m_countChekedPass = 0;
	std::string m_passFound = "not found";
private:
	int m_guessc[MAX_SIZE] = { }; // counter
	char m_guess[MAX_SIZE + 1];         // chars crresponding to counter
	const unsigned char m_chars[CHAR_COUNT + 1] =  "abcdefghijklmnopqrstuvwxyz0123456789";
};