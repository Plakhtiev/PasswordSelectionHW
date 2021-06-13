#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <iostream>
#include <stdio.h>
#include <memory>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "Timer.h"
#include "BruteForse.h"
#include "PasswordsChecker.h"
#include "FileStream.h"
#include "ProgressBar.hpp"



int main(int argc, char* argv[])
{
	
	const size_t quarter = pow(CHAR_COUNT, PASS_LENGTH) / 4;

	try
	{
		auto pbrf = std::make_shared<BruteForce>("chipher_text_brute_force");

		PasswordsChecker checker(pbrf);

		std::vector <std::string> passList1;
		std::vector <std::string> passList2;
		std::vector <std::string> passList3;
		std::vector <std::string> passList4;
		pbrf->GenerateGuess(passList1, quarter);
		pbrf->GenerateGuess(passList2, quarter);
		pbrf->GenerateGuess(passList3, quarter);
		pbrf->GenerateGuess(passList4, quarter);

		std::thread t_guess1([&]() {
			checker.PasswordGuessing(passList1);
			});
		std::thread t_guess2([&]() {
			checker.PasswordGuessing(passList2);
			});
		std::thread t_guess3([&]() {
			checker.PasswordGuessing(passList3);
			});
		std::thread t_guess4([&]() {
			checker.PasswordGuessing(passList4);
			});

		progresscpp::ProgressBar progressBar = checker.GetProgressBar();
		std::thread t_process([&]() {
			for (int i = 0; i < PASS_4_CHARS; i++) {
				++progressBar;
				if (i % 10000 == 0)
						progressBar.display();
					}			
			});

		t_process.join();	
		t_guess1.join();
		t_guess2.join();
		t_guess3.join();
		t_guess4.join();
		
		std::string pass  = checker.GetPassFound();
		std::cout << '\n' << "password was found - " << pass;
		
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
}