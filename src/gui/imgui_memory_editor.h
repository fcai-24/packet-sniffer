// ImGui Memory Editor v0.10
// https://github.com/ocornut/imgui_club

#pragma once

#include "imgui.h"

struct MemoryEditor {
    bool Open;
    bool ReadOnly;
    int Rows;
    int DataEditingAddr;
    bool DataEditingTakeFocus;
    char DataInput[32];
    char AddrInput[32];

    MemoryEditor() :
        Open(true), ReadOnly(false), Rows(16), DataEditingAddr(-1), DataEditingTakeFocus(false) {
        memset(DataInput, 0, sizeof(DataInput));
        memset(AddrInput, 0, sizeof(AddrInput));
    }

    void DrawWindow(const char* title, void* mem_data, size_t mem_size, size_t base_display_addr = 0) {
        if (!Open) return;

        ImGui::Begin(title, &Open);
        ImGui::PushItemWidth(80);

        size_t addr_digits_count = sizeof(size_t) * 2;
        size_t line_total_count = (mem_size + Rows - 1) / Rows;
        ImGuiListClipper clipper;
        clipper.Begin(line_total_count);
        while (clipper.Step()) {
            for (int line_i = clipper.DisplayStart; line_i < clipper.DisplayEnd; line_i++) {
                size_t addr = line_i * Rows;
                ImGui::Text("%0*X:", (int)addr_digits_count, base_display_addr + addr);
                ImGui::SameLine();

                for (int n = 0; n < Rows && addr < mem_size; n++, addr++) {
                    ImGui::SameLine();
                    if (DataEditingAddr == addr) {
                        ImGui::PushID((void*)addr);
                        if (DataEditingTakeFocus) {
                            ImGui::SetKeyboardFocusHere();
                            DataEditingTakeFocus = false;
                        }
                        ImGui::InputText(
                            "##data",
                            DataInput,
                            IM_ARRAYSIZE(DataInput),
                            ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
                        if (ImGui::IsItemDeactivated() ||
                            (ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_Enter))) {
                            // Apply the change
                            int data;
                            if (sscanf(DataInput, "%X", &data) == 1) {
                                ((unsigned char*)mem_data)[addr] = (unsigned char)data;
                            }
                            DataEditingAddr = -1;
                        }
                        ImGui::PopID();
                    } else {
                        unsigned char data = ((unsigned char*)mem_data)[addr];
                        ImGui::Text("%02X", data);
                        if (!ReadOnly && ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
                            DataEditingAddr = addr;
                            snprintf(DataInput, IM_ARRAYSIZE(DataInput), "%02X", data);
                            DataEditingTakeFocus = true;
                        }
                    }
                }
            }
        }
        ImGui::End();
    }
};

