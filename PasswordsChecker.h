#pragma once
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <memory>

#include "FileStream.h"
#include "BruteForse.h"
#include "ProgressBar.hpp"

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

class PasswordsChecker
{
public:

	PasswordsChecker(std::shared_ptr<BruteForce> generator);
	void PasswordGuessing(size_t count);
	progresscpp::ProgressBar GetProgressBar();
	std::string GetPassFound();
private:
	void PasswordToKey(std::string& password);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	void DencryptAes(const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decryptText);
private:
	const EVP_MD* m_dgst;
	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
private:
	std::shared_ptr<BruteForce> m_generator;
	std::vector<unsigned char> m_cipherOnlyText;
	std::vector<unsigned char> m_hashKey;
	std::string m_passFound;
private:
	progresscpp::ProgressBar m_progressBar;
};
