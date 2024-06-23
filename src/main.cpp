#include <mutex>
#include "Packet.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "core/core.hpp"
#include "gui-context.hpp"
#include "imgui.h"
#include "PcapLiveDeviceList.h"
#include "gui/imgui_memory_editor.h"

// this cuz windows and unix interpet 
// name and description differently
#if _WIN32 // windows
	#define DEVICE_NAME(d) d->getDesc().c_str()
#else // unix
	#define DEVICE_NAME(d) d->getName().c_str()
#endif

std::mutex packets_lock;

struct PacketStats {
	int ethPacketCount;
	int ipv4PacketCount;
	int ipv6PacketCount;
	int tcpPacketCount;
	int udpPacketCount;
	int dnsPacketCount;
	int httpPacketCount;
	int sslPacketCount;

	void clear() {
		ethPacketCount = 0;
		ipv4PacketCount = 0;
		ipv6PacketCount = 0;
		tcpPacketCount = 0;
		udpPacketCount = 0;
		tcpPacketCount = 0;
		dnsPacketCount = 0;
		httpPacketCount = 0;
		sslPacketCount = 0;
	}

	PacketStats() { clear(); }

	void consume_packet(pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet)) ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4)) ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6)) ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP)) tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP)) udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS)) dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP)) httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL)) sslPacketCount++;
	}

	void draw() {
		ImGui::Text("Ethernet packet count: %i", ethPacketCount);
		ImGui::TextColored(ImVec4(0, 1, 0, 1), "IPv4 packet count:     %i", ipv4PacketCount);
		ImGui::TextColored(ImVec4(0, 1, 0, 1), "IPv6 packet count:     %i", ipv6PacketCount);
		ImGui::TextColored(ImVec4(0.92, 0.4, 0.92, 1), "TCP packet count:      %i", tcpPacketCount);
		ImGui::TextColored(ImVec4(0.92, 0.4, 0.92, 1), "UDP packet count:      %i", udpPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "DNS packet count:      %i", dnsPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "HTTP packet count:     %i", httpPacketCount);
		ImGui::TextColored(ImVec4(0.4, 0.92, 0.92, 1), "SSL packet count:      %i", sslPacketCount);
	}
};

struct PacketsData {
	std::vector<pcpp::Packet> packets;
	PacketStats stats;
};

void on_packet(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice* device, void* data) {
	auto casted_data = static_cast<PacketsData*>(data);
	packets_lock.lock();
	auto packet = pcpp::Packet(raw_packet);
	casted_data->stats.consume_packet(packet);
	casted_data->packets.push_back(packet);
	packets_lock.unlock();
}

#if _WIN32
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
#else
int main() {
#endif

	ps::Log::init();
	MemoryEditor memory_editor{};

	auto device_list = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	pcpp::PcapLiveDevice* active_device = nullptr;

	struct {
		std::optional<pcpp::Packet> active_packet;
		pcpp::Layer* active_layer = nullptr;
		u64 active_packet_index = -1;
	} state;

	PacketsData data;

	// this should always be the last variable before 
	// the loop so it's the first to be cleaned
	// cuz we need the gui to desapier and then close other stuff
	ps::GuiContext gui_context{1280, 720, "Packet Sniffer"};
	while (!gui_context.should_close()) {
		gui_context.start_frame();

		ImGui::BeginMainMenuBar();
		if (ImGui::BeginMenu("file")) {
			if (ImGui::MenuItem("close")) { gui_context.close_window(); }
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();

		ImGui::Begin("Devices");
		for (auto device : device_list) {
			if (ImGui::Selectable(DEVICE_NAME(device), device->isOpened())) {
				if (active_device && active_device->isOpened()) {
					active_device->stopCapture();
					active_device->close();
					active_device = nullptr;
				}

				bool res = device->open();
				if (res) {
					active_device = device;
					active_device->setFilter("ip");
					active_device->startCapture(on_packet, &data);
				}
			};
		}
		ImGui::End();

		ImGui::Begin("Stats");
		packets_lock.lock();
		data.stats.draw();
		packets_lock.unlock();
		ImGui::End();

		if (active_device) {
			ImGui::Begin("Packets");
			packets_lock.lock();
			u64 i = 0;
			for (auto& packet : data.packets) {
				if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);
				std::string id = packet.getLastLayer()->toString() + "##" + std::to_string(i);

				auto layer = packet.getLastLayer()->getOsiModelLayer();
				if (layer == pcpp::OsiModelNetworkLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0, 1, 0, 1));
				else if (layer == pcpp::OsiModelTransportLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.92, 0.4, 0.92, 1));
				else if (layer == pcpp::OsiModelApplicationLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4, 0.92, 0.92, 1));
				else
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));

				if (ImGui::Selectable(id.c_str(), i == state.active_packet_index)) {
					state.active_packet = packet;
					state.active_packet_index = i;
				};

				ImGui::PopStyleColor();
				ImGui::Separator();
				i++;
			}
			packets_lock.unlock();
			ImGui::End();
		}

		if (state.active_packet.has_value()) {
			ImGui::Begin("Packet Inspector");
			auto layer = state.active_packet->getFirstLayer();
			while (layer) {
				if (layer->getOsiModelLayer() == pcpp::OsiModelNetworkLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0, 1, 0, 1));
				else if (layer->getOsiModelLayer() == pcpp::OsiModelTransportLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.92, 0.4, 0.92, 1));
				else if (layer->getOsiModelLayer() == pcpp::OsiModelApplicationLayer)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4, 0.92, 0.92, 1));
				else
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));

				ImGui::Text("%s", layer->toString().c_str());
				ImGui::PopStyleColor();

				layer = layer->getNextLayer();
			}
			ImGui::End();

			gui_context.push_font_mono();
			memory_editor.DrawWindow(
					"Raw Data",
					(void*)state.active_packet.value().getRawPacket()->getRawData(),
					state.active_packet.value().getRawPacket()->getRawDataLen());
			gui_context.pull_font_mono();
		}

		gui_context.end_frame();
	}

	if (active_device) {
		active_device->stopCapture();
		active_device->close();
	}

	return 0;
}
