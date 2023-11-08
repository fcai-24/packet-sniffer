#include "core/core.hpp"

#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "gui-context.hpp"
#include "imgui.h"

#include <GLFW/glfw3.h>

namespace ps {
	GuiContext::GuiContext(i32 width, i32 height, const char* name) {
		bool res = glfwInit();
		PS_ASSERT(res, "can't init glfw");

		window = glfwCreateWindow(width, height, "Packet Sniffer", nullptr, nullptr);
		PS_ASSERT(window, "can't create window");

		// set opengl context to be the current window
		glfwMakeContextCurrent(window);
		glfwSwapInterval(1);		// Enable vsync

		// imgui init
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGuiIO& io = ImGui::GetIO();
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;		 // Enable Keyboard Controls
		io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
		// io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

		ImGui_ImplGlfw_InitForOpenGL(window, true);
		ImGui_ImplOpenGL3_Init();
		ImGui::StyleColorsLight();
	}

	GuiContext::~GuiContext() {
		ImGui_ImplOpenGL3_Shutdown();
		ImGui_ImplGlfw_Shutdown();
		ImGui::DestroyContext();
		glfwDestroyWindow(window);
	}
}		 // namespace ps
