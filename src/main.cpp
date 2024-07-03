#include <algorithm>
#include <iterator>
#include <mutex>
#include <string_view>
#include "IPv4Layer.h"
#include "IpAddress.h"
#include "Packet.h"
#include "ProtocolType.h"
#include "RawPacket.h"
#include "TcpLayer.h"
#include "core/core.hpp"
#include "core/log.hpp"
#include "gui-context.hpp"
#include "imgui.h"
#include "PcapLiveDeviceList.h"
#include "gui/imgui_memory_editor.h"

#include "analyze.hpp"
#include "monitor.hpp"
#include "custom-protocols.hpp"

// this cuz windows and unix interpret
// name and description differently
#if _WIN32		// windows
	#define DEVICE_NAME(d) d->getDesc().c_str()
#else		 // unix
	#define DEVICE_NAME(d) d->getName().c_str()
#endif

#define BEACON_FRAME_SUBTYPE 8
#define SSID_ELEMENT_ID			 0

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

	void consume_packet(const pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet)) ethPacketCount++;
		if (packet.isPacketOfType(pcpp::IPv4)) ipv4PacketCount++;
		if (packet.isPacketOfType(pcpp::IPv6)) ipv6PacketCount++;
		if (packet.isPacketOfType(pcpp::TCP)) tcpPacketCount++;
		if (packet.isPacketOfType(pcpp::UDP)) udpPacketCount++;
		if (packet.isPacketOfType(pcpp::DNS)) dnsPacketCount++;
		if (packet.isPacketOfType(pcpp::HTTP)) httpPacketCount++;
		if (packet.isPacketOfType(pcpp::SSL)) sslPacketCount++;
	}

	void draw() const {
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

struct WebsocketConnection {
	pcpp::IPv4Address srcIP, dstIP;
	u16 srcPort, dstPort;

	WebsocketConnection(
			const pcpp::IPv4Address srcIP,
			const pcpp::IPv4Address dstIP,
			const u16 srcPort,
			const u16 dstPort): srcIP(srcIP), dstIP(dstIP), srcPort(srcPort), dstPort(dstPort) {}
};

struct PacketsData {
	std::vector<pcpp::Packet*> packets;
	std::vector<std::string> ssid;
	PacketStats stats;
	ps::AnalyticsWindow a;
	ps::MonitorMode monitor_mode;
	std::vector<WebsocketConnection> active_websocket_conns;
};

void print_active_sockets(const std::vector<WebsocketConnection>& sockets) {
	for (auto socket : sockets) {
		PS_INFO(
				"ACTIVE SOCKET: \n\tSRC: {}, PORT: {}\n\tDST: {}, PORT: {}",
				socket.srcIP.toString(),
				socket.srcPort,
				socket.dstIP.toString(),
				socket.dstPort);
	}
}

bool check_if_connection_exists(
		const WebsocketConnection& conn_to_find, const std::vector<WebsocketConnection>& active_conns) {
	const auto res = std::ranges::find_if(active_conns, [&](const WebsocketConnection& conn) {
		if (conn_to_find.srcIP == conn.srcIP && conn_to_find.srcPort == conn.srcPort &&
				conn_to_find.dstIP == conn.dstIP && conn_to_find.dstPort == conn.dstPort)
			return true;
		else if (
				conn_to_find.srcIP == conn.dstIP && conn_to_find.srcPort == conn.dstPort &&
				conn_to_find.dstIP == conn.srcIP && conn_to_find.dstPort == conn.srcPort)
			return true;
		return false;
	});
	if (res == active_conns.end()) return false;
	return true;
}

bool try_parse_websocket_handshake(const pcpp::Packet* packet, PacketsData* data) {
	const pcpp::Layer* lastLayer = packet->getLastLayer();
	if (lastLayer->getProtocol() != pcpp::GenericPayload && lastLayer->getProtocol() != pcpp::HTTP)
		return false;
	u8* payload = lastLayer->getData();
	std::string payload_str(payload, payload + lastLayer->getDataLen());
	std::string_view sv(std::begin(payload_str), std::end(payload_str));
	const size_t res1 = sv.find("Upgrade: websocket");
	const size_t res2 = sv.find("Connection: Upgrade");

	// Check if handshake response
	if (res1 != std::string_view::npos && res2 != std::string_view::npos) {
		const auto* ip = dynamic_cast<pcpp::IPv4Layer*>(packet->getLayerOfType(pcpp::IPv4));
		const auto* tcp = dynamic_cast<pcpp::TcpLayer*>(packet->getLayerOfType(pcpp::TCP));
		const pcpp::IPv4Address srcIP = ip->getSrcIPv4Address();
		const pcpp::IPv4Address dstIP = ip->getDstIPv4Address();
		const u16 srcPort = tcp->getSrcPort();
		const u16 dstPort = tcp->getDstPort();
		const WebsocketConnection connection(srcIP, dstIP, srcPort, dstPort);
		if (check_if_connection_exists(connection, data->active_websocket_conns)) return true;
		data->active_websocket_conns.push_back(connection);
		PS_INFO("Recognized websocket handshake");
		print_active_sockets(data->active_websocket_conns);
		return true;
	}
	return false;
};

void try_parse_websocket(pcpp::Packet* packet, PacketsData* data) {
	pcpp::Layer* last = packet->getLastLayer();
	if (last->getProtocol() != pcpp::GenericPayload) return;
	const auto* tcp = dynamic_cast<pcpp::TcpLayer*>(packet->getLayerOfType(pcpp::TCP));
	if (tcp == nullptr) return;
	const auto* ip = dynamic_cast<pcpp::IPv4Layer*>(packet->getLayerOfType(pcpp::IPv4));
	const pcpp::IPv4Address srcIP = ip->getSrcIPv4Address();
	const pcpp::IPv4Address dstIP = ip->getDstIPv4Address();
	const u16 srcPort = tcp->getSrcPort();
	const u16 dstPort = tcp->getDstPort();
	if (!check_if_connection_exists({srcIP, dstIP, srcPort, dstPort}, data->active_websocket_conns))
		return;
	PS_INFO(
			"FOUND WEBSOCKET PACKET (BEFORE PARSE). size: {}, header: {}, payload: {}",
			last->getDataLen(),
			last->getHeaderLen(),
			last->getLayerPayloadSize());
	// ps::WebsocketLayer* ws = new ps::WebsocketLayer(last->getData(), last->getDataLen(),
	// last->getPrevLayer(), packet);
	auto* ws = new ps::WebsocketLayer(last);
	packet->removeLastLayer();
	packet->addLayer(ws, true);
	packet->computeCalculateFields();
	auto hdr = ws->getHeader();
	PS_INFO(
			"FIN: {}, RSV1: {}, RSV2: {}, RSV3: {}\nOPCODE: {}, MASK: {}, PAYLOAD_LEN: {}",
			(bool)hdr->fin,
			(bool)hdr->rsv1,
			(bool)hdr->rsv2,
			(bool)hdr->rsv3,
			(u8)hdr->opcode,
			(bool)hdr->mask,
			ws->getPayloadLen());
}

void on_packet(pcpp::RawPacket* raw_packet, pcpp::PcapLiveDevice* device, void* data) {
	if (!device) return;

	packets_lock.lock();
	auto casted_data = static_cast<PacketsData*>(data);
	// if (!ps::is_ieee802_11_packet(raw_packet->getRawData(), raw_packet->getRawDataLen())) {
		auto packet = new pcpp::Packet(raw_packet);
		if (!try_parse_websocket_handshake(packet, casted_data))
			try_parse_websocket(packet, casted_data);
		casted_data->stats.consume_packet(*packet);
		casted_data->a.consume(*packet, device, casted_data->packets.size());
		casted_data->packets.push_back(packet);
	// } else {
		// casted_data->monitor_mode.parse_packet(raw_packet->getRawData(), raw_packet->getRawDataLen());
	// }
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
		pcpp::Packet* active_packet = nullptr;
		pcpp::Layer* active_layer = nullptr;
		u64 active_packet_index = -1;
		std::string cur_filter;
		bool monitor_mode = false;
	} state;

	PacketsData data;

	bool graph = false;

	// this should always be the last variable before
	// the loop so it's the first to be cleaned
	// cuz we need the gui to disappear and then close other stuff
	ps::GuiContext gui_context{1280, 720, "Packet Sniffer"};
	while (!gui_context.should_close()) {
		gui_context.start_frame();

		ImGui::BeginMainMenuBar();
		if (ImGui::BeginMenu("file")) {
			if (ImGui::MenuItem("Toggle graph")) { graph = !graph; }
			if (ImGui::MenuItem("Toggle monitor")) { state.monitor_mode = !state.monitor_mode; }
			if (ImGui::MenuItem("close")) { gui_context.close_window(); }
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();

		ImGui::Begin("Devices");
		ImGui::Text("Filter:");
		ImGui::SameLine();
		if (ImGui::InputText(
						"##filter", state.cur_filter.data(), 1000, ImGuiInputTextFlags_EnterReturnsTrue)) {
			state.cur_filter = state.cur_filter.data();		 // NOLINT(*-redundant-string-cstr)
			if (active_device) {
				// Set filter and print error to log if exists
				if (active_device->setFilter(state.cur_filter)) {
					PS_INFO("FILTER SET: " + state.cur_filter);
				} else {
					PS_ERROR("Cannot set filter: {}", state.cur_filter);
				}
			}
		}
		for (auto device : device_list) {
			if (ImGui::Selectable(DEVICE_NAME(device), device->isOpened())) {
				if (active_device && active_device->isOpened()) {
					active_device->stopCapture();
					active_device->close();
					active_device = nullptr;
				}

				// Open device and check for errors
				if (device->open()) {
					PS_INFO("Opened device: {}", DEVICE_NAME(device));
				} else {
					PS_ERROR("Cannot open device: {}", DEVICE_NAME(device));
				}
				active_device = device;
				// Set filter if exists
				if (state.cur_filter.empty())
					active_device->setFilter("ip");
				else
					active_device->setFilter(state.cur_filter);

				active_device->startCapture(on_packet, &data);
			};
		}
		ImGui::End();

		ImGui::Begin("Stats");
		packets_lock.lock();
		data.stats.draw();
		packets_lock.unlock();
		ImGui::End();

		if (graph) {
			packets_lock.lock();
			data.a.draw();
			packets_lock.unlock();
		} else if (state.monitor_mode) {
			packets_lock.lock();
			data.monitor_mode.draw();
			packets_lock.unlock();
		} else {
			if (active_device){
				ImGui::Begin("Packets");
				packets_lock.lock();
				u64 i = 0;
				for (auto& packet : data.packets) {
					if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);
					std::string id = packet->getLastLayer()->toString() + "##" + std::to_string(i);

					auto layer = packet->getLastLayer()->getOsiModelLayer();
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

				if (!data.ssid.empty()) {
					for (auto& ssid : data.ssid) {
						if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(0.0f);

						ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.8, 0.7, 0.3, 1));
						ImGui::Selectable(ssid.c_str(), false);
						ImGui::PopStyleColor();
						ImGui::Separator();
					}
				}
				packets_lock.unlock();
				ImGui::End();
			}

			if (state.active_packet != nullptr) {
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
						(void*)state.active_packet->getRawPacket()->getRawData(),
						state.active_packet->getRawPacket()->getRawDataLen());
				gui_context.pull_font_mono();
			}
		}

		gui_context.end_frame();
	}

	if (active_device) {
		active_device->stopCapture();
		active_device->close();
	}

	return 0;
}
