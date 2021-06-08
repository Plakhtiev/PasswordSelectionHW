#include "Timer.h"

Timer::Timer()
{
	m_start = std::chrono::high_resolution_clock::now();
}

Timer::~Timer()
{
	m_end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<float> duration = m_end - m_start;
	std::cout << '\n' << "Duration " << duration.count() << " s" << std::endl;
}