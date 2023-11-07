#include "core/log.hpp"
#include "gui-context.hpp"
#include "imgui.h"
#include "spdlog/spdlog.h"

int main(int argc, char *argv[]) {
	ps::Log::init();
	ps::GuiContext gui_context{1280, 720, "Packet Sniffer"};

	while (!gui_context.should_close()) {
		gui_context.start_frame();

		ImGui::BeginMainMenuBar();
		if (ImGui::BeginMenu("file")) {
			if (ImGui::MenuItem("close")) { gui_context.close_window(); }
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();

    ImGui::Text("Helloo!");

		gui_context.end_frame();
	}

	return 0;
}
