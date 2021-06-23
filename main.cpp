#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <stdio.h>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

#include "Timer.h"
#include "PasswordsChecker.h"
#include "FileStream.h"
#include "ProgressBar.hpp"



int main(int argc, char* argv[])
{
	Timer timer;
	const size_t sizeSupposedPass = 4;
	const size_t numberSupposedPass = pow(36, sizeSupposedPass);
	std::cout << "Start programm please wait" << '\n';

	try
	{
		

		PasswordsChecker checker("chipher_text_brute_force");

		std::thread t_guess1([&]() {
			checker.PasswordGuessing(numberSupposedPass / 4);
			});
		std::thread t_guess2([&]() {
			checker.PasswordGuessing(numberSupposedPass / 4);
			});
		std::thread t_guess3([&]() {
			checker.PasswordGuessing(numberSupposedPass / 4);
			});
		std::thread t_guess4([&]() {
			checker.PasswordGuessing(numberSupposedPass / 4);
			});

		progresscpp::ProgressBar progressBar = checker.GetProgressBar();
		std::thread t_process([&]() {
			for (int i = 0; i < numberSupposedPass; i++) {
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