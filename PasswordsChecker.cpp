#include "PasswordsChecker.h"

std::mutex mtx;

PasswordsChecker::PasswordsChecker(const std::string pathFile) :
	m_chars("abcdefghijklmnopqrstuvwxyz0123456789"),
	m_progressBar(progresscpp::ProgressBar(PASS_4_CHARS, 70, '#', '-')),
	m_key{},
	m_iv{}
{
	/* Initialize digests table */
	OpenSSL_add_all_digests();
	m_dgst = EVP_get_digestbyname("md5");

	for (int i = 1; i < MAX_SIZE; m_guessCounter[i++] = -1);        // initializing counter with -1
	for (int i = 0; i <= MAX_SIZE; m_guess[i++] = '\0');     // initializing guess with NULL

	std::vector<unsigned char> chipherText;
	ReadFile(pathFile, chipherText);

	const size_t size = chipherText.size() - 32; // size text without hash
	size_t i = 0;
	auto begin = chipherText.begin();
	auto end = chipherText.end();

	for (; begin != end; ++begin, ++i) {
		if (i < size) {
			m_cipherOnlyText.push_back(*begin);//get text without hash
		}
		if (i >= size) {
			m_hashKey.push_back(*begin);//get hash from file
		}
	}
}


progresscpp::ProgressBar PasswordsChecker::GetProgressBar()
{
	return m_progressBar;
}

std::string PasswordsChecker::GetPassFound()
{
	return m_passFound;
}

void PasswordsChecker::GenerateGuess(std::vector<std::string>& guessPassList, const size_t countGeneratePass)
{
	std::lock_guard<std::mutex> grd(mtx);
	int i, j;

	while (m_countGuess++ < pow(CHAR_COUNT, PASS_LENGTH) && countGeneratePass >= m_countGuess)
	{
		// increment guessc[i+1] if guessc[i] is bigger than the number of chars in the array
		i = 0;
		while (m_guessCounter[i] == CHAR_COUNT)    // check all counter elements wether theire value is bigger than the number of chars stored in CHAR_COUNT or not
		{
			m_guessCounter[i] = 0;                // reset the element that is bigger than CHAR_COUNT to 0
			m_guessCounter[++i] += 1;             // increment the next element (index i+1)
		}

		for (j = 0; j <= i; ++j)   // change all chars that differ from the last guess (the number of chars changed is equal to the number of counter elements tested(=i))
		{
			if (j < MAX_SIZE) // check if an element guess[j] exists
				m_guess[j] = m_chars[m_guessCounter[j]];
		}

		//printf("%s\n", m_guess);   // printf is used since it is way faster than std::cout
		//		
		guessPassList.emplace_back(m_guess);

		++m_guessCounter[0];    // increment guessc at index 0 for the next run
	}

	m_countGuess = 0; //reset count Guess
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



void PasswordsChecker::PasswordGuessing(size_t count)
{
	std::vector<std::string> generatedPass;
	GenerateGuess(generatedPass, count);//generate and write passwords guess

	auto begin = generatedPass.begin();
	auto end = generatedPass.end();
	for (; begin != end; ++begin) {
		
		PasswordToKey(*begin);
		
		std::vector<unsigned char> dencryptTextRes;
		DencryptAes(m_cipherOnlyText, dencryptTextRes);// try decrypt with pass

		std::vector<unsigned char> hash;
		CalculateHash(dencryptTextRes, hash);//calculate hash decrypt text

		if (hash == m_hashKey) {// compare the hash
			m_passFound = *begin;
			return;
		}
	}
}