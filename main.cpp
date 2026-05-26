#include "hdr.h"

#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>

#define endl '\n'
using namespace std;

const char* redirect_msg =
	"HTTP/1.0 302 Redirect\r\n"
	"Location: http://warning.or.kr\r\n"
	"\r\n";

void usage(){
	cerr << "syntax : tcp-block <interface> <pattern>" << endl;
	cerr << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"" << endl;
}

uint16_t checksum(const void* data, size_t len){
	const uint8_t* p = (const uint8_t*)(data);
	uint32_t sum = 0;

	while(len > 1){
		sum += (uint16_t)((p[0] << 8) | p[1]);
		p += 2;
		len -= 2;
	}

	if(len == 1) sum += (uint16_t)(p[0] << 8);

	while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

	return htons((uint16_t)(~sum));
}

uint16_t tcp_checksum(const ip_hdr* ip, const tcp_hdr* tcp, const uint8_t* data, size_t data_len){
	struct pseudo_hdr{
		uint32_t sip;
		uint32_t dip;
		uint8_t zero;
		uint8_t protocol;
		uint16_t tcp_len;
	};

	pseudo_hdr pseudo{};
	size_t tcp_len = sizeof(tcp_hdr) + data_len;

	pseudo.sip = ip->sip;
	pseudo.dip = ip->dip;
	pseudo.zero = 0;
	pseudo.protocol = ip_hdr::TCP;
	pseudo.tcp_len = htons((uint16_t)(tcp_len));

	vector<uint8_t> buf(sizeof(pseudo_hdr) + tcp_len);
	memcpy(buf.data(), &pseudo, sizeof(pseudo_hdr));
	memcpy(buf.data() + sizeof(pseudo_hdr), tcp, sizeof(tcp_hdr));

	if(data_len > 0)
		memcpy(buf.data() + sizeof(pseudo_hdr) + sizeof(tcp_hdr), data, data_len);

	return checksum(buf.data(), buf.size());
}

bool find_pattern(const uint8_t* data, size_t data_len, const string& pattern){
	if(pattern.empty() || data_len < pattern.size()) return false;

	const uint8_t* begin = data;
	const uint8_t* end = data + data_len;
	const uint8_t* p_begin = (const uint8_t*)(pattern.data());
	const uint8_t* p_end = p_begin + pattern.size();

	return search(begin, end, p_begin, p_end) != end;
}

void make_ip(ip_hdr* ip, uint16_t len, uint32_t sip, uint32_t dip){
	ip->v_hl = 0x45;
	ip->tos = 0;
	ip->len = htons(len);
	ip->id = 0;
	ip->off = 0;
	ip->ttl = 64;
	ip->p = ip_hdr::TCP;
	ip->sum = 0;
	ip->sip = sip;
	ip->dip = dip;
	ip->sum = checksum(ip, sizeof(ip_hdr));
}

void make_tcp(tcp_hdr* tcp, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags){
	tcp->sport = sport;
	tcp->dport = dport;
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off_rsv = (uint8_t)((sizeof(tcp_hdr) / 4) << 4);
	tcp->flags = flags;
	tcp->win = htons(0);
	tcp->sum = 0;
	tcp->urp = 0;
}

bool send_rst(pcap_t* handle, const eth_hdr* old_eth, const ip_hdr* old_ip, const tcp_hdr* old_tcp, size_t old_data_len){
	size_t packet_len = sizeof(eth_hdr) + sizeof(ip_hdr) + sizeof(tcp_hdr);
	vector<uint8_t> packet(packet_len);

	auto eth = (eth_hdr*)(packet.data());
	auto ip = (ip_hdr*)(packet.data() + sizeof(eth_hdr));
	auto tcp = (tcp_hdr*)(packet.data() + sizeof(eth_hdr) + sizeof(ip_hdr));

	memcpy(eth, old_eth, sizeof(eth_hdr));
	eth->type = htons(eth_hdr::IP4);

	uint32_t seq = ntohl(old_tcp->seq) + (uint32_t)(old_data_len);
	uint32_t ack = ntohl(old_tcp->ack);

	make_ip(ip, sizeof(ip_hdr) + sizeof(tcp_hdr), old_ip->sip, old_ip->dip);
	make_tcp(tcp, old_tcp->sport, old_tcp->dport, seq, ack, tcp_hdr::RST | tcp_hdr::ACK);
	tcp->sum = tcp_checksum(ip, tcp, nullptr, 0);

	return pcap_sendpacket(handle, packet.data(), (int)(packet.size())) == 0;
}

bool send_fin(int raw_s, const ip_hdr* old_ip, const tcp_hdr* old_tcp, size_t old_data_len){
	const uint8_t* data = (const uint8_t*)(redirect_msg);
	size_t data_len = strlen(redirect_msg);
	size_t packet_len = sizeof(ip_hdr) + sizeof(tcp_hdr) + data_len;

	vector<uint8_t> packet(packet_len);

	auto ip = (ip_hdr*)(packet.data());
	auto tcp = (tcp_hdr*)(packet.data() + sizeof(ip_hdr));
	auto tcp_data = packet.data() + sizeof(ip_hdr) + sizeof(tcp_hdr);

	memcpy(tcp_data, data, data_len);

	uint32_t seq = ntohl(old_tcp->ack);
	uint32_t ack = ntohl(old_tcp->seq) + (uint32_t)(old_data_len);

	make_ip(ip, (uint16_t)(packet_len), old_ip->dip, old_ip->sip);
	make_tcp(tcp, old_tcp->dport, old_tcp->sport, seq, ack, tcp_hdr::FIN | tcp_hdr::ACK);
	tcp->sum = tcp_checksum(ip, tcp, tcp_data, data_len);

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = old_ip->sip;
	addr.sin_port = old_tcp->sport;

	auto sent = sendto(raw_s, packet.data(), packet.size(), 0, (sockaddr*)(&addr), sizeof(addr));
	return sent == (ssize_t)(packet.size());
}

void block_packet(pcap_t* handle, int raw_s, const eth_hdr* eth, const ip_hdr* ip, const tcp_hdr* tcp, size_t data_len){
	bool rst = send_rst(handle, eth, ip, tcp, data_len);
	bool fin = send_fin(raw_s, ip, tcp, data_len);

	char sip[INET_ADDRSTRLEN];
	char dip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ip->sip, sip, sizeof(sip));
	inet_ntop(AF_INET, &ip->dip, dip, sizeof(dip));

	cout << "blocked "
	     << sip << ':' << ntohs(tcp->sport) << " -> "
	     << dip << ':' << ntohs(tcp->dport)
	     << " rst=" << (rst ? "ok" : "fail")
	     << " fin302=" << (fin ? "ok" : "fail")
	     << endl;
}

int main(int argc, char* argv[]){
	if(argc != 3){
		usage();
		return 1;
	}

	char* dev = argv[1];
	string pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if(handle == nullptr){
		cerr << "pcap_open_live(" << dev << ") failed: " << errbuf << endl;
		return 1;
	}

	int raw_s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(raw_s == -1){
		perror("socket");
		pcap_close(handle);
		return 1;
	}

	int opt = 1;
	if(setsockopt(raw_s, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1){
		perror("setsockopt");
		close(raw_s);
		pcap_close(handle);
		return 1;
	}

	while(true){
		pcap_pkthdr* header;
		const uint8_t* packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
			cerr << "pcap_next_ex failed: " << pcap_geterr(handle) << endl;
			break;
		}

		if(header->caplen < sizeof(eth_hdr) + sizeof(ip_hdr)) continue;
		auto eth = (eth_hdr*)packet;
		if(ntohs(eth->type) != eth_hdr::IP4) continue;
		
		auto ip = (ip_hdr*)(packet + sizeof(eth_hdr));
		if(ip->p != ip_hdr::TCP) continue;
		
		size_t ip_hl = ip->hl();
		size_t ip_len = ntohs(ip->len);
		if(ip_hl < sizeof(ip_hdr)) continue;
		if(ip_len < ip_hl + sizeof(tcp_hdr)) continue;
		
		size_t tcp_offset = sizeof(eth_hdr) + ip_hl;
		if(header->caplen < tcp_offset + sizeof(tcp_hdr)) continue;
		
		auto tcp = (tcp_hdr*)(packet + tcp_offset);
		size_t tcp_hl = tcp->off();
		if(tcp_hl < sizeof(tcp_hdr)) continue;
		if(ip_len < ip_hl + tcp_hl) continue;
		
		size_t data_len = ip_len - ip_hl - tcp_hl;
		size_t data_offset = tcp_offset + tcp_hl;
		if(data_len == 0 || header->caplen < data_offset + data_len) continue;
		
		auto data = packet + data_offset;
		if(!find_pattern(data, data_len, pattern)) continue;
		
		block_packet(handle, raw_s, eth, ip, tcp, data_len);
	}

	close(raw_s);
	pcap_close(handle);

	return 0;
}
