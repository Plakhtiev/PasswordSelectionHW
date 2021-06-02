#include <string>
#include <vector>

#include <iostream>
#include <stdio.h>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "Timer.h"
#include "BruteForse.h"
#include "FileStream.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void PasswordToKey(std::string password)
{
	/* Initialize digests table */

	OpenSSL_add_all_digests();

	const EVP_MD* dgst = EVP_get_digestbyname("md5");
	if (!dgst)
	{
		throw std::runtime_error("no such digest");
	}

	const unsigned char* salt = NULL;
	if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		reinterpret_cast<unsigned char*>(&password[0]),
		password.size(), 1, key, iv))
	{
		throw std::runtime_error("EVP_BytesToKey failed");
	}
}

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
	{
		throw std::runtime_error("EncryptInit error");
	}

	std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
	int chipherTextSize = 0;
	if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Encrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("EncryptFinal error");
	}
	chipherTextSize += lastPartLen;
	chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

	chipherText.swap(chipherTextBuf);

	EVP_CIPHER_CTX_free(ctx);
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &data[0], data.size());
	SHA256_Final(&hashTmp[0], &sha256);

	hash.swap(hashTmp);
}

void Encrypt()
{
	std::vector<unsigned char> plainText;
	ReadFile("plain_text.txt", plainText);

	std::vector<unsigned char> hash;
	CalculateHash(plainText, hash);

	std::vector<unsigned char> chipherText;
	EncryptAes(plainText, chipherText);

	WriteFile("chipher_text.txt", chipherText);

	AppendToFile("chipher_text.txt", hash);
}

void DencryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& decryptText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
	{
		throw std::runtime_error("DecryptInit error");
	}

	//EVP_CIPHER_CTX_set_padding(ctx, 0);

	std::vector<unsigned char> chipherTextBuf(chipherText.size());
	int chipherTextSize = 0;
	if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &chipherText[0], chipherText.size())) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("Dencrypt error");
	}

	int lastPartLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
		EVP_CIPHER_CTX_free(ctx);
		throw std::runtime_error("DencryptFinal error");
	}
	chipherTextSize += lastPartLen;
	chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

	decryptText.swap(chipherTextBuf);

	EVP_CIPHER_CTX_free(ctx);
}

void Decrypt()
{
	std::vector<unsigned char> chipherText;
	ReadFile("chipher_text.txt", chipherText);

	std::vector<unsigned char> hash;
	CalculateHash(chipherText, hash);

	std::vector<unsigned char> chipherTextRes;
	DencryptAes(chipherText, chipherTextRes);

	WriteFile("decrypt_text.txt", chipherTextRes);
}

void DecryptForBruteForce() {
	std::vector<unsigned char> chipherText;
	ReadFile("chipherOnlytext.txt", chipherText);

	std::vector<unsigned char> hash;
	CalculateHash(chipherText, hash);

	std::vector<unsigned char> chipherTextRes;
	DencryptAes(chipherText, chipherTextRes);

	WriteFile("decryptChipherOnlytext.txt", chipherTextRes);
}

std::vector<unsigned char> HashFileText(const std::string& filePath) {
	std::vector<unsigned char> bruteForceText;
	ReadFile(filePath, bruteForceText);

	const int sizeHash = 32;
	auto begin = bruteForceText.begin() + (bruteForceText.size() - sizeHash);
	auto end = bruteForceText.end();

	std::vector<unsigned char> hashKey;
	for (;begin != end; ++begin) {
		hashKey.push_back(*begin);
	}
	return hashKey;
}

std::vector<unsigned char> OnlyText(std::vector<unsigned char>& cryptText) {
	const int sizeHash = 32;
	auto begin = cryptText.begin() + (cryptText.size() - sizeHash);
	cryptText.erase(begin, cryptText.end());
	return cryptText;
}

//std::vector<unsigned char> hashTxt = HashFileText("chipher_text.txt");
//std::vector<unsigned char> onlyChiperText;

//void GetTextForDecrypt() {
//	std::string str = "¦~s&Cq'´þtÏà7Ó";
//
//	std::vector<unsigned char> chipherText;
//	ReadFile("chipher_text.txt", chipherText);
//	std::vector<unsigned char> onlyChiperText = OnlyText(chipherText);
//	WriteFile("chipherOnlytext.txt", chipherText);
//}

int main(int argc, char* argv[])
{
	Timer timer;

	std::string pass = "b";
	BruteForce br("chipher_text.txt");
	br.GetGuess(100);

	try
	{
		PasswordToKey(pass);
		//Encrypt();
		//Decrypt();
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
}