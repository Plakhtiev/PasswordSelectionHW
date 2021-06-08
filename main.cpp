#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <iostream>
#include <stdio.h>
#include <future>
#include <windows.h>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "Timer.h"
#include "BruteForse.h"
#include "FileStream.h"

std::mutex mtxPassGen;

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
		//throw std::runtime_error("DencryptFinal error");
		decryptText.push_back('0');
		return;
	}
	chipherTextSize += lastPartLen;
	chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

	decryptText.swap(chipherTextBuf);

	EVP_CIPHER_CTX_free(ctx);
}

void Decrypt()
{
	std::vector<unsigned char> chipherText;
	ReadFile("chipherOnlytext.txt", chipherText);

	std::vector<unsigned char> chipherTextRes;
	DencryptAes(chipherText, chipherTextRes);

	WriteFile("decryptChipherOnlytext.txt", chipherTextRes);
}

void PaswordGuessing(BruteForce& brf) {
	//std::lock_guard<std::mutex> grd(mtxPassGen);

	std::vector<std::string> generatedPass = brf.GetGeneratedPass();

	auto begin = generatedPass.begin() + brf.GetCountChekedPass();
	auto end = generatedPass.end();
	for (; begin != end; ++begin) {
		PasswordToKey(*begin);
		std::vector<unsigned char> dencryptTextRes;
		DencryptAes(brf.Get—ipherOnlyText(), dencryptTextRes);
		std::vector<unsigned char> hash;
		CalculateHash(dencryptTextRes, hash);
		brf.SetCountChekedPass(1);
		if (hash == brf.GetHashKey()) {
			brf.SetFoundPass(*begin);
			std::cout << '\n' << "password was found - " << *begin;
			return;
		}
	}
}

int main(int argc, char* argv[])
{
	Timer timer;

	std::string pass = "b";
	const size_t quarter = pow(CHAR_COUNT, PASS_LENGTH) / 4;

	try
	{
		BruteForce br("chipher_text_brute_force");

		br.GenerateGuess();
		PaswordGuessing(br);
		/*std::thread t_guess1([&]() {
			PaswordGuessing1(br);
			});*/

			
		std::cout << '\n' << br.GetCountChekedPass();

		//PasswordToKey(pass);
		//Encrypt();
		//Decrypt();
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
}