#pragma once

#include <iostream>
#include <stdio.h>
#include <math.h>
#include <string>
#include <vector>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "FileStream.h"

#define MAX_SIZE 30         // only used to avoid errors
#define CHAR_COUNT 36       // size of the charset you want to use (number of possible chars for the password)
#define PASS_LENGTH 4

class BruteForce
{
public:
	BruteForce(const std::string pathFile);
	void GetGuess(const size_t countGeneratePass = pow(CHAR_COUNT, PASS_LENGTH));
	std::string GetFoundPass();
	void SetFoundPass(std::string pass);
	std::vector<std::string> GetGeneratedPass();
	std::vector<std::string> GetGeneratedPass(size_t beginIndex);
	std::vector<unsigned char> GetHashKey();
	std::vector<unsigned char> Get—ipherOnlyText();

private:
	std::vector<std::string> m_guessPassList;
	std::vector<unsigned char> m_guessVecHash;
	std::vector<unsigned char> m_hashKey;
	std::vector<unsigned char> m_cipherOnlyText;// text without hash
	size_t m_countGuess = 0;
	std::string m_passFound = "not found";
private:
	int m_guessc[MAX_SIZE] = { }; // counter
	unsigned char m_guess[MAX_SIZE + 1];         // chars crresponding to counter
	const unsigned char m_chars[CHAR_COUNT + 1] = "abcdefghijklmnopqrstuvwxyz0123456789";
};