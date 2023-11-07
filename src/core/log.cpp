#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "log.hpp"

namespace ps {

	Ref<spdlog::logger> Log::core_logger;

	void Log::init() {
		std::vector<spdlog::sink_ptr> logSinks;
		logSinks.emplace_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
		logSinks.emplace_back(
				std::make_shared<spdlog::sinks::basic_file_sink_mt>("packet-sniffer.log", true));

		logSinks[0]->set_pattern("%^[%T] %n: %v%$");
		logSinks[1]->set_pattern("[%T] [%l] %n: %v");

		core_logger =
				std::make_shared<spdlog::logger>("Packet-Sniffer", begin(logSinks), end(logSinks));
		spdlog::register_logger(core_logger);
		core_logger->set_level(spdlog::level::trace);
		core_logger->flush_on(spdlog::level::trace);
	}

}		 // namespace ps
