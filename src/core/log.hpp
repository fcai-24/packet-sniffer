#pragma once

#include "core.hpp"

// This ignores all warnings raised inside External headers
#pragma warning(push, 0)
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>
#pragma warning(pop)

namespace ps {
	class Log {
	public:
		static void init();
		static Ref<spdlog::logger> core_logger;
	};

}		 // namespace ps

#define PS_TRACE(...)		 ::ps::Log::core_logger->trace(__VA_ARGS__)
#define PS_INFO(...)		 ::ps::Log::core_logger->info(__VA_ARGS__)
#define PS_WARN(...)		 ::ps::Log::core_logger->warn(__VA_ARGS__)
#define PS_ERROR(...)		 ::ps::Log::core_logger->error(__VA_ARGS__)
#define PS_CRITICAL(...) ::ps::Log::core_logger->critical(__VA_ARGS__)
#define PS_ASSERT(to_check, ...)                 \
	{                                              \
		if (!(to_check)) {                           \
			PS_ERROR("Assert failed {}", __VA_ARGS__); \
			abort();                                   \
		}                                            \
	}
