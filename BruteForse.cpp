#include "BruteForse.h"

std::mutex mtx;

BruteForce::BruteForce(const std::string pathFile) :
	m_chars("abcdefghijklmnopqrstuvwxyz0123456789")
{
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

void BruteForce::GenerateGuess(std::vector<std::string>& guessPassList, const size_t countGeneratePass)
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


std::vector<unsigned char> BruteForce::GetHashKey()
{
	return m_hashKey;
}

std::vector<unsigned char> BruteForce::GetCipherOnlyText()
{
	return m_cipherOnlyText;
}