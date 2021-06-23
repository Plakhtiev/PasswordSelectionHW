#pragma once
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <memory>
#include <mutex>
#include <string_view>

#include "FileStream.h"
#include "ProgressBar.hpp"

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"


class PasswordsChecker
{
public:

	PasswordsChecker(const std::string& pathFile, size_t supposedPassLength = 4);
	void PasswordGuessing(size_t count);
	progresscpp::ProgressBar GetProgressBar();
	std::string GetPassFound();

	
	void GenerateGuess(std::vector<std::string>& guessPassList, const size_t countGeneratePass = pow(m_charCount, m_supposedPassLength));
	size_t GetCountGeneratePass();
private:
	void PasswordToKey(std::string& password);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	void DencryptAes(const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decryptText);
private:
	const EVP_MD* m_dgst;
	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
	static const size_t m_maxSize = 10; // only used to avoid errors
	static const size_t m_charCount = 36; // size of the charset you want to use (number of possible chars for the password)
	static const size_t m_supposedPassLength = 4;
	const size_t m_countGeneratePass = pow(m_charCount, m_supposedPassLength);
	
private:
	int m_guessCounter[m_maxSize] = { };
	char m_guess[m_maxSize + 1];         // chars crresponding to counter
	const unsigned char m_chars[m_charCount + 1];

	std::vector<unsigned char> m_hashKey;
	std::vector<unsigned char> m_cipherOnlyText;// text without hash
	size_t m_countGuess = 0;
	std::string m_passFound;
private:
	progresscpp::ProgressBar m_progressBar;
	std::mutex m_mtx;
};
