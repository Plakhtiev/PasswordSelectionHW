#include "BruteForse.h"

BruteForce::BruteForce(const std::string pathFile)
{
	for (int i = 1; i < MAX_SIZE; m_guessc[i++] = -1);        // initializing counter with -1
	for (int i = 0; i <= MAX_SIZE; m_guess[i++] = '\0');     // initializing guess with NULL

	//get hash from file
	std::vector<unsigned char> chipherText;
	ReadFile(pathFile, chipherText);

	const int sizeHash = 32;
	auto begin = chipherText.begin() + (chipherText.size() - sizeHash);
	auto end = chipherText.end();

	for (;begin != end; ++begin) {
		m_hashKey.push_back(*begin);
	}
}


void BruteForce::GetGuess(const size_t countGeneratePass)
{
	int i, j;

	while (m_countGuess++ < pow(CHAR_COUNT, PASS_LENGTH) && countGeneratePass >= m_countGuess)
	{
		// increment guessc[i+1] if guessc[i] is bigger than the number of chars in the array
		i = 0;
		while (m_guessc[i] == CHAR_COUNT)    // check all counter elements wether theire value is bigger than the number of chars stored in CHAR_COUNT or not
		{
			m_guessc[i] = 0;                // reset the element that is bigger than CHAR_COUNT to 0
			m_guessc[++i] += 1;             // increment the next element (index i+1)
		}

		for (j = 0;j <= i;++j)   // change all chars that differ from the last guess (the number of chars changed is equal to the number of counter elements tested(=i))
		{
			if (j < MAX_SIZE) // check if an element guess[j] exists
				m_guess[j] = m_chars[m_guessc[j]];
		}
		// output the guess to std::out
		printf("%s\n", m_guess);   // printf is used since it is way faster than std::cout
		std::string str;
		for (int k = 0; m_guess[k] != '\0'; ++k) {
			str.push_back(m_guess[k]);			
		}
		m_guessPassList.push_back(str);

		str.erase();

		++m_guessc[0];    // increment guessc at index 0 for the next run
	}

	m_countGuess = 0; //reset count Guess
}

std::string BruteForce::GetFoundPass()
{
	return m_passFound;
}

std::vector<std::string> BruteForce::GetGeneratedPass()
{
	return m_guessPassList;
}

std::vector<std::string> BruteForce::GetGeneratedPass(size_t beginIndex)
{
	auto begin = m_guessPassList.begin() + beginIndex;
	auto end = m_guessPassList.end();

	std::vector<std::string> result;
	for (;begin != end; ++begin) {
		result.push_back(*begin);
	}
	return result;
}

std::vector<unsigned char> BruteForce::GetHashKey()
{
	return m_hashKey;
}
