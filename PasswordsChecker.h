#pragma once
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <memory>

#include "FileStream.h"
#include "BruteForse.h"

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

class PasswordsChecker
{
public:

	PasswordsChecker(std::shared_ptr<BruteForce> generator);
	void PasswordGuessing(std::vector<std::string> generatedPass);
private:
	void PasswordToKey(std::string& password);
	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);
	void DencryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& decryptText);
private:
	const EVP_MD* m_dgst;
	unsigned char m_key[EVP_MAX_KEY_LENGTH];
	unsigned char m_iv[EVP_MAX_IV_LENGTH];
	size_t m_proceesBarIndex = 0;
private:
	std::shared_ptr<BruteForce> m_generator;
	std::vector<unsigned char> m_cipherOnlyText;
	std::vector<unsigned char> m_hashKey;
};
