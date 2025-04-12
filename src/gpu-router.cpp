#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>      // Required for struct ip
#include <netinet/ip6.h>     // Required for struct ip6_hdr
#include <netinet/tcp.h>     // Required for IPPROTO_TCP
#include <netinet/udp.h>     // Required for IPPROTO_UDP
#include <netinet/ip_icmp.h> // Required for IPPROTO_ICMP and IPPROTO_ICMPV6

#include <sycl/sycl.hpp>

#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include "dpc_common.hpp"

const size_t burst_size = 32;
#define PACKET_SIZE 64
typedef struct my_packet
{
    const u_char *packet;
    struct pcap_pkthdr *header;
} my_packet;
bool my_packet_handler_ip(
    const struct pcap_pkthdr *header,
    const u_char *packet)
{
    // Ensure packet is large enough for Ethernet header
    if (header->caplen < sizeof(struct ether_header))
    {
        // fprintf(stderr, "Packet too short for Ethernet header (%u bytes)\n", header->caplen);
        return false;
    }

    const struct ether_header *eth_header = (const struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    const u_char *ip_payload = packet + sizeof(struct ether_header);
    uint32_t remaining_len = header->caplen - sizeof(struct ether_header);
    std::vector<const u_char *> packets_ipv4(burst_size);
    std::vector<const u_char *> packets_ipv6(burst_size);
    // Check for IPv4
    if (ether_type == ETHERTYPE_IP)
    {
        if (remaining_len < sizeof(struct ip))
        {
            // fprintf(stderr, "Packet too short for IPv4 header\n");
            return false;
        }
        const struct ip *ip_hdr = (const struct ip *)ip_payload;

        // Check actual IPv4 header length
        uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
        if (remaining_len < ip_hdr_len)
        {
            // fprintf(stderr, "Packet too short for full IPv4 header (required %u)\n", ip_hdr_len);
            return false;
        }

        uint8_t protocol = ip_hdr->ip_p;
        bool is_ICMP_OR_TCP_OR_UDP = (protocol == IPPROTO_ICMP || protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
        return is_ICMP_OR_TCP_OR_UDP;
    }
    if (ether_type == ETHERTYPE_IPV6)
    {
        if (remaining_len < sizeof(struct ip6_hdr))
        {
            // fprintf(stderr, "Packet too short for IPv6 header\n");
            return false;
        }
        const struct ip6_hdr *ip6_hdr = (const struct ip6_hdr *)ip_payload;

        // Note: This is a simplified check. IPv6 can have extension headers.
        // A full implementation would need to parse these.
        uint8_t next_header = ip6_hdr->ip6_nxt;
        bool is_ICMP_OR_TCP_OR_UDP = (next_header == IPPROTO_ICMPV6 || next_header == IPPROTO_TCP || next_header == IPPROTO_UDP);
        return is_ICMP_OR_TCP_OR_UDP;
    }
    return false;
}
// Function to print packet information
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
int main()
{
    // Initialize pcap
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the capture file
    handle = pcap_open_offline("../../src/capture1.pcap", errbuf);
    if (handle == NULL)
    {
        std::cerr << "Couldn't open capture1.pcap: " << errbuf << std::endl;
        return 1;
    }
    sycl::queue q;

    std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << std::endl;

    int nth = 10; // number of threads
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Input node: get packets from the socket or from the packet capture
    tbb::flow::input_node<std::vector<my_packet>> in_node{
        g,
        [&](tbb::flow_control &fc) -> std::vector<my_packet>
        {
            int nr_packets = 0;
            const u_char *packet;
            struct pcap_pkthdr header;
            std::vector<my_packet> packets(burst_size);
            std::cout << "Input node running " << std::endl;
            // Read a batch of packets from the pcap file
            for (int i = 0; i < burst_size; i++)
            {
                packet = pcap_next(handle, &header);
                if (packet == NULL)
                {
                    if (nr_packets == 0)
                    {
                        std::cout << packets.size() << std::endl;
                        return packets;
                    }
                    break;
                }
                my_packet temp = {packet, &header};
                packets[i] = temp;
                // Here you would process/store the packet
                // Example: copy packet data to a buffer for processing

                nr_packets++;
            }
            // Attempt to read the packets from the packet capture or read
            // them from a network socket
            packet = NULL;
            if (packet == NULL)
            {
                std::cout << packets.size() << std::endl;
                return packets;
            }

            // Return the number of packets read
            return packets;
        }};

    // Packet inspection node
    tbb::flow::function_node<std::vector<my_packet>, int> inspect_packet_node{
        g, tbb::flow::unlimited, [&](const std::vector<my_packet> &packets) -> int
        {
            // By including all the SYCL work in a {} block, we ensure
            // all SYCL tasks must complete before exiting the block
            {
                sycl::queue gpuQ(sycl::default_selector_v, dpc_common::exception_handler);

                std::cout << "Selected GPU Device Name: " << gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";
                std::vector<my_packet> ip_packets(burst_size);
                struct pcap_pkthdr header;
                for (auto temp : packets)
                {
                    if (my_packet_handler_ip(temp.header, temp.packet))
                    {
                        ip_packets.emplace_back(temp);
                    }
                }
                int nr_packets = static_cast<int>(ip_packets.size());
                if (nr_packets == 0)
                {
                    std::cout << "Inspect node received 0 packets." << std::endl;
                    return 0; // Return 0 if no packets to process
                }

                gpuQ.submit([&](sycl::handler &h)
                            {
                                // Capture packets by value for the kernel if needed, or handle pointers carefully
                                auto compute = [=](auto i)
                                {
                                    // Process the packets[i]
                                    // Ensure you are only processing valid packets up to nr_packets
                                    if (i < nr_packets)
                                    {
                                        // Example: Access packet data (be mindful of data lifetime if using pointers directly)
                                        // const u_char* current_packet = packets[i];
                                        // Process current_packet...
                                    }
                                };

                                h.parallel_for(nr_packets, compute); // Use the actual count
                            })
                    .wait_and_throw(); // end of the commands for the SYCL queue

            } // End of the scope for SYCL code; the queue has completed the work

            // Return the number of packets processed
            return static_cast<int>(packets.size()); // Or return nr_packets if that's more appropriate
        }};
    // construct graph
    tbb::flow::make_edge<std::vector<my_packet>>(in_node, inspect_packet_node);

    in_node.activate();
    g.wait_for_all();

    std::cout << "Done waiting" << std::endl;
}
