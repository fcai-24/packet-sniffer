#pragma once

#include "imgui.h"
#include "ImNodeFlow.h"
#include "Packet.h"
#include "EthLayer.h"
#include <array>

using namespace ImFlow;

namespace ps {

	class Computer: public BaseNode {
	public:
		Computer(std::string mac_addr, bool host = false) {
			setTitle(mac_addr);
			setStyle(host ? NodeStyle::red() : NodeStyle::green());

			addIN<int>("ETH", 0, ConnectionFilter::SameType());
			addIN<int>("IPv4", 0, ConnectionFilter::SameType());
			addIN<int>("IPv6", 0, ConnectionFilter::SameType());
			addIN<int>("TCP", 0, ConnectionFilter::SameType());
			addIN<int>("UDP", 0, ConnectionFilter::SameType());
			addIN<int>("DNS", 0, ConnectionFilter::SameType());
			addIN<int>("HTTP", 0, ConnectionFilter::SameType());
			addIN<int>("SSL", 0, ConnectionFilter::SameType());

			addOUT<int>("ETH")->behaviour([this]() { return 0; });
			addOUT<int>("IPv4")->behaviour([this]() { return 0; });
			addOUT<int>("IPv6")->behaviour([this]() { return 0; });
			addOUT<int>("TCP")->behaviour([this]() { return 0; });
			addOUT<int>("UDP")->behaviour([this]() { return 0; });
			addOUT<int>("DNS")->behaviour([this]() { return 0; });
			addOUT<int>("HTTP")->behaviour([this]() { return 0; });
			addOUT<int>("SSL")->behaviour([this]() { return 0; });
		}

		void draw() override {}
	};

	class AnalyticsWindow {
	public:
		AnalyticsWindow() { window = ImFlow::ImNodeFlow(); }

		void draw() {
			ImGui::Begin("In Depth Analyitics");
			window.update();
			ImGui::End();
		}

		void consume(const pcpp::Packet& packet, pcpp::PcapLiveDevice* device, u64 packet_index) {
			if (!device || !device->getMacAddress().isValid()) {
				PS_WARN("ignoring a packet due to a bad interface mac addr");
				return;
			}

			bool new_host = false;
			pcpp::MacAddress host_mac = device->getMacAddress();
			if (!host_interfaces.contains(host_mac.toString())) {
				host_interfaces[host_mac.toString()] =
						window.addNode<Computer>({0, c}, host_mac.toString(), true);
				c += 200;
				new_host = true;
			}

			auto host_node = host_interfaces[host_mac.toString()];
			auto eth_layer = dynamic_cast<pcpp::EthLayer*>(packet.getFirstLayer());

			if (host_mac != eth_layer->getDestMac()) {
				// outgoing packet

				bool new_other = false;
				pcpp::MacAddress other_mac = eth_layer->getSourceMac();
				if (!interfaces.contains(other_mac.toString())) {
					interfaces[other_mac.toString()] =
							window.addNode<Computer>({300, co}, other_mac.toString());
					co += 220;
					new_other = true;
				}

				auto other_node = interfaces[other_mac.toString()];
				out_packets[other_node].push_back(packet_index);

				if (!new_host && !new_other) return;

				u32 i = 0;
				auto ins = other_node->getIns();
				for (auto out : host_node->getOuts()) {
					if (out->getName() == "ETH" && packet.isPacketOfType(pcpp::Ethernet)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "IPv4" && packet.isPacketOfType(pcpp::IPv4)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "IPv6" && packet.isPacketOfType(pcpp::IPv6)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "TCP" && packet.isPacketOfType(pcpp::TCP)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "UDP" && packet.isPacketOfType(pcpp::UDP)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "DNS" && packet.isPacketOfType(pcpp::DNS)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "HTTP" && packet.isPacketOfType(pcpp::HTTP)) {
						out->createLink(ins[i].get());
					}
					if (out->getName() == "SSL" && packet.isPacketOfType(pcpp::SSL)) {
						out->createLink(ins[i].get());
					}

					i++;
				}

			} else {
				// incomming packet
			}
		}

	private:
		f32 c = 10;
		f32 co = 10;
		ImFlow::ImNodeFlow window;
		std::unordered_map<std::string, std::shared_ptr<Computer>> host_interfaces;
		std::unordered_map<std::string, std::shared_ptr<Computer>> interfaces;
		std::unordered_map<std::shared_ptr<Computer>, std::vector<u64>> in_packets;
		std::unordered_map<std::shared_ptr<Computer>, std::vector<u64>> out_packets;
		// std::vector<std::shared_ptr<Link>> links;
	};
}		 // namespace ps
