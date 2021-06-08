#pragma once
#include <chrono>
#include <iostream>
class Timer
{
public:
	Timer();
	~Timer();
private:
	std::chrono::time_point<std::chrono::steady_clock> m_start, m_end;
};
