#pragma once
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <memory>
#include <mutex>

#include "FileStream.h"
#include "ProgressBar.hpp"

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#define MAX_SIZE 10         // only used to avoid errors
#define CHAR_COUNT 36       // size of the charset you want to use (number of possible chars for the password)
#define PASS_LENGTH 4
#define PASS_3_CHARS 46656
#define PASS_4_CHARS 1679616

class PasswordsChecker
{
public:

	PasswordsChecker(const std::string pathFile);
	void PasswordGuessing(size_t count);
	progresscpp::ProgressBar GetProgressBar();
	std::string GetPassFound();

	
	void GenerateGuess(std::vector<std::string>& guessPassList, const size_t countGeneratePass = pow(CHAR_COUNT, PASS_LENGTH));

private:
	void PasswordToKey(std::string& password);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	void DencryptAes(const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decryptText);
private:
	const EVP_MD* m_dgst;
	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
private:
	int m_guessCounter[MAX_SIZE] = { };
	char m_guess[MAX_SIZE + 1];         // chars crresponding to counter
	const unsigned char m_chars[CHAR_COUNT + 1];

	std::vector<unsigned char> m_hashKey;
	std::vector<unsigned char> m_cipherOnlyText;// text without hash
	size_t m_countGuess = 0;
	std::string m_passFound;
private:
	progresscpp::ProgressBar m_progressBar;
};
