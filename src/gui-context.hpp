#pragma once
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "core/core.hpp"
#include "imgui.h"

#include <GLFW/glfw3.h>

namespace ps {
	class GuiContext {
	public:
		GuiContext(i32 width, i32 height, const char* window_name);
		~GuiContext();

		bool should_close() const { return glfwWindowShouldClose(window); }
		void close_window() { glfwSetWindowShouldClose(window, 1); }

		void start_frame() const {
			glfwPollEvents();

			ImGui_ImplOpenGL3_NewFrame();
			ImGui_ImplGlfw_NewFrame();
			ImGui::NewFrame();

			// clearing last frame
			glClear(GL_COLOR_BUFFER_BIT);
			ImGui::DockSpaceOverViewport();
		}

		void end_frame() const {
			// imgui render
			ImGui::Render();
			ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

			ImGuiIO& io = ImGui::GetIO();
			if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
				ImGui::UpdatePlatformWindows();
				ImGui::RenderPlatformWindowsDefault();
			}

			// Swap front and back buffers
			glfwSwapBuffers(window);
		}

		void push_font_mono() { ImGui::PushFont(mono); }
		void pull_font_mono() { ImGui::PopFont(); }

	private:
		GLFWwindow* window;
		ImFont* mono;
	};
}		 // namespace ps
