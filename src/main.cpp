#include <mutex>
#include "Packet.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "core/core.hpp"
#include "gui-context.hpp"
#include "imgui.h"
#include "PcapLiveDeviceList.h"
#include "gui/imgui_memory_editor.h"
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#if _WIN32
	#define DEVICE_NAME(d) d->getDesc().c_str()
#else
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
				ImVec4 color;
				switch (layer->getOsiModelLayer()) {
					case pcpp::OsiModelNetworkLayer: color = ImVec4(0, 1, 0, 1); break;
					case pcpp::OsiModelTransportLayer: color = ImVec4(0.92, 0.4, 0.92, 1); break;
					case pcpp::OsiModelApplicationLayer: color = ImVec4(0.4, 0.92, 0.92, 1); break;
					default: color = ImVec4(1, 1, 1, 1); break;
				}
				ImGui::PushStyleColor(ImGuiCol_Text, color);

				// Display detailed layer information
				ImGui::Text("%s", layer->toString().c_str());

				// Additional details based on layer type
				switch (layer->getProtocol()) {
					case pcpp::Ethernet:
						ImGui::Text(
								"Source MAC: %s", ((pcpp::EthLayer*)layer)->getSourceMac().toString().c_str());
						ImGui::Text(
								"Destination MAC: %s", ((pcpp::EthLayer*)layer)->getDestMac().toString().c_str());
						break;
					case pcpp::IPv4: {
						auto ipv4Layer = dynamic_cast<pcpp::IPv4Layer*>(layer);
						if (ipv4Layer) {
							ImGui::Text("Header Length: %u", ipv4Layer->getHeaderLen());
							ImGui::Text("TTL: %u", ipv4Layer->getIPv4Header()->timeToLive);
						}
						break;
					}

					case pcpp::IPv6: {
						auto ipv6Layer = dynamic_cast<pcpp::IPv6Layer*>(layer);
						if (ipv6Layer) {
							ImGui::Text("Header Length: %u", ipv6Layer->getHeaderLen());
							ImGui::Text("Hop Limit (TTL): %u", ipv6Layer->getIPv6Header()->hopLimit);
						}
						break;
					}

					case pcpp::TCP: {
						auto tcpLayer = dynamic_cast<pcpp::TcpLayer*>(layer);
						if (tcpLayer) {
							ImGui::Text("Source Port: %d", tcpLayer->getSrcPort());
							ImGui::Text("Destination Port: %d", tcpLayer->getDstPort());
							ImGui::Text("Sequence Number: %u", tcpLayer->getTcpHeader()->sequenceNumber);
							ImGui::Text("Acknowledgment Number: %u", tcpLayer->getTcpHeader()->ackNumber);
							ImGui::Text("Flags:");
							if (tcpLayer->getTcpHeader()->synFlag) ImGui::Text("    SYN");
							if (tcpLayer->getTcpHeader()->ackFlag) ImGui::Text("    ACK");
							if (tcpLayer->getTcpHeader()->finFlag) ImGui::Text("    FIN");
						}
						break;
					}

					case pcpp::UDP: {
						auto udpLayer = dynamic_cast<pcpp::UdpLayer*>(layer);
						if (udpLayer) {
							ImGui::Text("Source Port: %d", udpLayer->getSrcPort());
							ImGui::Text("Destination Port: %d", udpLayer->getDstPort());
						}
						break;
					}
				}

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

#if _WIN32
	return 0;
#endif
}