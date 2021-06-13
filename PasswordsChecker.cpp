#include "PasswordsChecker.h"

PasswordsChecker::PasswordsChecker(std::shared_ptr<BruteForce> generator) :
	m_generator(generator),
	m_cipherOnlyText(generator->GetCipherOnlyText()),
	m_hashKey(generator->GetHashKey()),
	m_progressBar(progresscpp::ProgressBar(PASS_4_CHARS, 70, '#', '-'))

{
	/* Initialize digests table */
	OpenSSL_add_all_digests();
	m_dgst = EVP_get_digestbyname("md5");
}


progresscpp::ProgressBar PasswordsChecker::GetProgressBar()
{
	return m_progressBar;
}

std::string PasswordsChecker::GetPassFound()
{
	return m_passFound;
}

void PasswordsChecker::PasswordToKey(std::string& password)
{
	if (!m_dgst)
	{
		throw std::runtime_error("no such digest");
	}

	const unsigned char* salt = NULL;
	if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		reinterpret_cast<unsigned char*>(&password[0]),
		password.size(), 1, m_key, m_iv))
	{
		throw std::runtime_error("EVP_BytesToKey failed");
	}
}

void PasswordsChecker::CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &data[0], data.size());
	SHA256_Final(&hashTmp[0], &sha256);

	hash.swap(hashTmp);
}

void PasswordsChecker::DencryptAes(const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decryptText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
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

void PasswordsChecker::PasswordGuessing(std::vector<std::string> generatedPass)
{
	auto begin = generatedPass.begin();
	auto end = generatedPass.end();
	for (; begin != end; ++begin) {
		
		PasswordToKey(*begin);
		
		std::vector<unsigned char> dencryptTextRes;
		DencryptAes(m_cipherOnlyText, dencryptTextRes);
		std::vector<unsigned char> hash;
		CalculateHash(dencryptTextRes, hash);

		if (hash == m_hashKey) {
			m_passFound = *begin;
			return;
		}
	}
}