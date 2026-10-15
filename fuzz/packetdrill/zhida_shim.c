// packetdrill shared-object shim: script packets cross the tap-echo net_tap netdev.
// netdev_send frames packetdrill's IPv4 bytes and writes them to an AF_PACKET socket on
// the kernel side of the tap; netdev_receive returns the IPv4 bytes of Zhida's frames.
// Before the script starts, warm_arp fills Zhida's neighbor cache with the tester.
// packetdrill calls every syscall entry without a NULL check (run_system_call.c), so each
// one aborts: scripts are packet-only.
// check_cpu fails the run unless packetdrill may run only on PACKETDRILL_CPU (run.sh pins
// it there, apart from tap-echo, so its timing checks never wait for Zhida's CPU).

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "packetdrill.h"

#define IFACE_UP_TIMEOUT_MS 10000
#define ARP_WARMUP_TIMEOUT_MS 10000
#define ARP_WARMUP_RESEND_MS 100
#define RECEIVE_POLL_MS 10
#define MAX_FRAME 2048

struct shim {
	int fd;
	unsigned char zhida_mac[ETH_ALEN];
	unsigned char tester_mac[ETH_ALEN];
	struct in_addr zhida_ip;
	struct in_addr tester_ip;
};

static _Noreturn void die(const char *message)
{
	fprintf(stderr, "zhida_shim: %s\n", message);
	exit(1);
}

static _Noreturn void die_errno(const char *what)
{
	fprintf(stderr, "zhida_shim: %s: %s\n", what, strerror(errno));
	exit(1);
}

static const char *env(const char *name)
{
	const char *value = getenv(name);
	if (value == NULL) {
		fprintf(stderr, "zhida_shim: %s is not set\n", name);
		abort();
	}
	return value;
}

static void check_cpu(void)
{
	const char *name = env("PACKETDRILL_CPU");
	char *end;
	errno = 0;
	long cpu = strtol(name, &end, 10);
	if (errno != 0 || end == name || *end != '\0' || cpu < 0 || cpu >= CPU_SETSIZE) {
		fprintf(stderr, "zhida_shim: PACKETDRILL_CPU is not a CPU number: %s\n", name);
		abort();
	}
	cpu_set_t set;
	if (sched_getaffinity(0, sizeof(set), &set) < 0)
		die_errno("sched_getaffinity");
	if (CPU_COUNT(&set) != 1 || !CPU_ISSET(cpu, &set)) {
		fprintf(stderr, "zhida_shim: packetdrill may run on %d CPU(s), not only CPU %ld\n",
			CPU_COUNT(&set), cpu);
		exit(1);
	}
}

static void parse_mac(const char *name, unsigned char mac[ETH_ALEN])
{
	const char *text = env(name);
	char tail;
	if (sscanf(text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%c", &mac[0], &mac[1],
		   &mac[2], &mac[3], &mac[4], &mac[5], &tail) != 6) {
		fprintf(stderr, "zhida_shim: %s=%s is not a MAC address\n", name, text);
		abort();
	}
}

static void parse_ip(const char *name, struct in_addr *ip)
{
	const char *text = env(name);
	if (inet_pton(AF_INET, text, ip) != 1) {
		fprintf(stderr, "zhida_shim: %s=%s is not an IPv4 address\n", name, text);
		abort();
	}
}

// Wait until the netdev exists and is IFF_UP; return its ifindex.
static int wait_iface_up(int fd, const char *iface)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if (strlen(iface) >= sizeof(ifr.ifr_name))
		die("ZHIDA_IFACE is too long");
	strcpy(ifr.ifr_name, iface);
	for (int waited = 0; waited <= IFACE_UP_TIMEOUT_MS; waited += 10) {
		if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
			if (ifr.ifr_flags & IFF_UP) {
				unsigned index = if_nametoindex(iface);
				if (index == 0)
					die_errno("if_nametoindex");
				return (int)index;
			}
		} else if (errno != ENODEV) {
			die_errno("SIOCGIFFLAGS");
		}
		usleep(10000);
	}
	fprintf(stderr, "zhida_shim: %s not up after %d ms\n", iface, IFACE_UP_TIMEOUT_MS);
	exit(1);
}

static _Noreturn void unsupported(void)
{
	fprintf(stderr, "syscall lines are not supported by the Zhida shim\n");
	abort();
}

#define UNSUPPORTED(name, ret, ...) \
	static ret unsupported_##name(void *userdata, __VA_ARGS__) { unsupported(); }

UNSUPPORTED(socket, int, int domain, int type, int protocol)
UNSUPPORTED(bind, int, int fd, const struct sockaddr *addr, socklen_t len)
UNSUPPORTED(listen, int, int fd, int backlog)
UNSUPPORTED(accept, int, int fd, struct sockaddr *addr, socklen_t *len)
UNSUPPORTED(connect, int, int fd, const struct sockaddr *addr, socklen_t len)
UNSUPPORTED(read, ssize_t, int fd, void *buf, size_t count)
UNSUPPORTED(readv, ssize_t, int fd, const struct iovec *iov, int iovcnt)
UNSUPPORTED(recv, ssize_t, int fd, void *buf, size_t len, int flags)
UNSUPPORTED(recvfrom, ssize_t, int fd, void *buf, size_t len, int flags,
	    struct sockaddr *addr, socklen_t *addrlen)
UNSUPPORTED(recvmsg, ssize_t, int fd, struct msghdr *msg, int flags)
UNSUPPORTED(write, ssize_t, int fd, const void *buf, size_t count)
UNSUPPORTED(writev, ssize_t, int fd, const struct iovec *iov, int iovcnt)
UNSUPPORTED(send, ssize_t, int fd, const void *buf, size_t len, int flags)
UNSUPPORTED(sendto, ssize_t, int fd, const void *buf, size_t len, int flags,
	    const struct sockaddr *addr, socklen_t addrlen)
UNSUPPORTED(sendmsg, ssize_t, int fd, const struct msghdr *msg, int flags)
UNSUPPORTED(fcntl, int, int fd, int cmd, ...)
UNSUPPORTED(ioctl, int, int fd, unsigned long request, ...)
UNSUPPORTED(close, int, int fd)
UNSUPPORTED(shutdown, int, int fd, int how)
UNSUPPORTED(getsockopt, int, int fd, int level, int name, void *val, socklen_t *len)
UNSUPPORTED(setsockopt, int, int fd, int level, int name, const void *val, socklen_t len)
UNSUPPORTED(poll, int, struct pollfd *fds, nfds_t nfds, int timeout)
UNSUPPORTED(epoll_create, int, int size)
UNSUPPORTED(epoll_ctl, int, int epfd, int op, int fd, struct epoll_event *event)
UNSUPPORTED(epoll_wait, int, int epfd, struct epoll_event *events, int max, int timeout)
UNSUPPORTED(pipe, int, int fds[2])
UNSUPPORTED(splice, int, int in, loff_t *in_off, int out, loff_t *out_off, size_t len,
	    unsigned int flags)

static void shim_free(void *userdata)
{
	struct shim *shim = userdata;
	close(shim->fd);
	free(shim);
}

// Write one frame; packetdrill's netdev contract is 0 on success, -1 on error.
static int send_frame(struct shim *shim, const void *frame, size_t len)
{
	ssize_t sent = send(shim->fd, frame, len, 0);
	if (sent < 0) {
		fprintf(stderr, "zhida_shim: send: %s\n", strerror(errno));
		return -1;
	}
	if ((size_t)sent != len) {
		fprintf(stderr, "zhida_shim: short send: %zd of %zu bytes\n", sent, len);
		return -1;
	}
	return 0;
}

static int shim_netdev_send(void *userdata, const void *buf, size_t count)
{
	struct shim *shim = userdata;
	unsigned char frame[MAX_FRAME];
	struct ether_header *eth = (struct ether_header *)frame;
	if (count > sizeof(frame) - sizeof(*eth)) {
		fprintf(stderr, "zhida_shim: %zu-byte IP packet exceeds the frame buffer\n", count);
		return -1;
	}
	memcpy(eth->ether_dhost, shim->zhida_mac, ETH_ALEN);
	memcpy(eth->ether_shost, shim->tester_mac, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_IP);
	memcpy(frame + sizeof(*eth), buf, count);
	return send_frame(shim, frame, sizeof(*eth) + count);
}

static bool arp_header_ok(const struct ether_arp *arp)
{
	return ntohs(arp->arp_hrd) == ARPHRD_ETHER && ntohs(arp->arp_pro) == ETHERTYPE_IP &&
	       arp->arp_hln == ETH_ALEN && arp->arp_pln == sizeof(struct in_addr);
}

// Zhida's reply to warm_arp's request: Ethernet destination TESTER_MAC, from
// ZHIDA_MAC/ZHIDA_IP to TESTER_MAC/TESTER_IP, nothing else. Bytes after the ARP
// payload (Ethernet padding) are allowed. Callers have checked Ethernet source and type.
static bool is_warmup_reply(const struct shim *shim, const unsigned char *frame, size_t len)
{
	const struct ether_header *eth = (const struct ether_header *)frame;
	const struct ether_arp *arp = (const struct ether_arp *)(frame + ETH_HLEN);
	return len >= ETH_HLEN + sizeof(*arp) &&
	       memcmp(eth->ether_dhost, shim->tester_mac, ETH_ALEN) == 0 &&
	       arp_header_ok(arp) && ntohs(arp->arp_op) == ARPOP_REPLY &&
	       memcmp(arp->arp_sha, shim->zhida_mac, ETH_ALEN) == 0 &&
	       memcmp(arp->arp_spa, &shim->zhida_ip, sizeof(struct in_addr)) == 0 &&
	       memcmp(arp->arp_tha, shim->tester_mac, ETH_ALEN) == 0 &&
	       memcmp(arp->arp_tpa, &shim->tester_ip, sizeof(struct in_addr)) == 0;
}

// Answer Zhida's ARP request for TESTER_IP.
static void reply_arp(struct shim *shim, const struct ether_arp *request)
{
	struct {
		struct ether_header eth;
		struct ether_arp arp;
	} __attribute__((packed)) reply;
	memcpy(reply.eth.ether_dhost, shim->zhida_mac, ETH_ALEN);
	memcpy(reply.eth.ether_shost, shim->tester_mac, ETH_ALEN);
	reply.eth.ether_type = htons(ETHERTYPE_ARP);
	reply.arp.arp_hrd = htons(ARPHRD_ETHER);
	reply.arp.arp_pro = htons(ETHERTYPE_IP);
	reply.arp.arp_hln = ETH_ALEN;
	reply.arp.arp_pln = sizeof(struct in_addr);
	reply.arp.arp_op = htons(ARPOP_REPLY);
	memcpy(reply.arp.arp_sha, shim->tester_mac, ETH_ALEN);
	memcpy(reply.arp.arp_spa, &shim->tester_ip, sizeof(struct in_addr));
	memcpy(reply.arp.arp_tha, request->arp_sha, ETH_ALEN);
	memcpy(reply.arp.arp_tpa, request->arp_spa, sizeof(struct in_addr));
	if (send_frame(shim, &reply, sizeof(reply)))
		exit(1);
}

// Zhida's ARP frames (Ethernet source ZHIDA_MAC) must be well-formed Ethernet/IPv4
// requests from ZHIDA_MAC/ZHIDA_IP, as Linux requires before answering, or replies
// to warm_arp's request; anything else is a Zhida bug: print the frame and exit 1.
// Requests for TESTER_IP get a reply. A warm-up-shaped reply is accepted at any time in
// the run, not only during warm_arp: resends can draw duplicates that arrive after the
// first reply. Only an exact match passes, so a stray reply Zhida sent mid-script would
// be the exact answer to a request the tester did make, valid ARP either way.
static void check_arp(struct shim *shim, const unsigned char *frame, size_t len)
{
	const struct ether_arp *arp = (const struct ether_arp *)(frame + ETH_HLEN);
	if (len >= ETH_HLEN + sizeof(*arp) && arp_header_ok(arp) &&
	    ntohs(arp->arp_op) == ARPOP_REQUEST &&
	    memcmp(arp->arp_sha, shim->zhida_mac, ETH_ALEN) == 0 &&
	    memcmp(arp->arp_spa, &shim->zhida_ip, sizeof(struct in_addr)) == 0) {
		if (memcmp(arp->arp_tpa, &shim->tester_ip, sizeof(struct in_addr)) == 0)
			reply_arp(shim, arp);
		return;
	}
	if (is_warmup_reply(shim, frame, len))
		return;
	fprintf(stderr, "zhida_shim: malformed ARP frame from Zhida (%zu bytes):", len);
	for (size_t i = 0; i < len; i++)
		fprintf(stderr, " %02x", frame[i]);
	fprintf(stderr, "\n");
	exit(1);
}

static long long monotonic_ms(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		die_errno("clock_gettime");
	return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// Fill Zhida's neighbor cache before the script starts, so that its first SYN-ACK does
// not wait on an ARP exchange. smoltcp fills the cache from any ARP request aimed at its
// address (src/iface/interface/ipv4.rs 293-301) and keeps the entry 60 s
// (src/iface/neighbor.rs 56); every unicast IPv4 packet from the tester's MAC refreshes
// it (ipv4.rs 214-219), so only 60 s without tester traffic makes Zhida ARP again,
// which check_arp answers. tap-echo may not serve the port yet (packetdrill starts before
// EAL init), so the request is resent every ARP_WARMUP_RESEND_MS until Zhida's reply
// comes, and exit 1 after ARP_WARMUP_TIMEOUT_MS. Other ARP frames from Zhida go through
// check_arp; anything else is ignored, as netdev_receive ignores it.
static void warm_arp(struct shim *shim)
{
	struct {
		struct ether_header eth;
		struct ether_arp arp;
	} __attribute__((packed)) request;
	memset(&request, 0, sizeof(request));
	memset(request.eth.ether_dhost, 0xff, ETH_ALEN);
	memcpy(request.eth.ether_shost, shim->tester_mac, ETH_ALEN);
	request.eth.ether_type = htons(ETHERTYPE_ARP);
	request.arp.arp_hrd = htons(ARPHRD_ETHER);
	request.arp.arp_pro = htons(ETHERTYPE_IP);
	request.arp.arp_hln = ETH_ALEN;
	request.arp.arp_pln = sizeof(struct in_addr);
	request.arp.arp_op = htons(ARPOP_REQUEST);
	memcpy(request.arp.arp_sha, shim->tester_mac, ETH_ALEN);
	memcpy(request.arp.arp_spa, &shim->tester_ip, sizeof(struct in_addr));
	memcpy(request.arp.arp_tpa, &shim->zhida_ip, sizeof(struct in_addr));

	long long deadline = monotonic_ms() + ARP_WARMUP_TIMEOUT_MS;
	long long resend_at = 0;
	for (;;) {
		long long now = monotonic_ms();
		if (now >= deadline) {
			fprintf(stderr, "zhida_shim: no ARP reply from Zhida within %d ms\n",
				ARP_WARMUP_TIMEOUT_MS);
			exit(1);
		}
		if (now >= resend_at) {
			if (send_frame(shim, &request, sizeof(request)))
				exit(1);
			resend_at = now + ARP_WARMUP_RESEND_MS;
		}
		long long wait = (resend_at < deadline ? resend_at : deadline) - now;
		struct pollfd pfd = {.fd = shim->fd, .events = POLLIN};
		int ready = poll(&pfd, 1, (int)wait);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			die_errno("poll");
		}
		if (ready == 0)
			continue;

		unsigned char frame[MAX_FRAME];
		struct sockaddr_ll from;
		socklen_t from_len = sizeof(from);
		ssize_t len = recvfrom(shim->fd, frame, sizeof(frame), MSG_TRUNC,
				       (struct sockaddr *)&from, &from_len);
		if (len < 0)
			die_errno("recvfrom");
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		if ((size_t)len > sizeof(frame)) {
			fprintf(stderr, "zhida_shim: %zd-byte frame exceeds the frame buffer\n", len);
			exit(1);
		}
		const struct ether_header *eth = (const struct ether_header *)frame;
		if ((size_t)len < sizeof(*eth) || ntohs(eth->ether_type) != ETHERTYPE_ARP ||
		    memcmp(eth->ether_shost, shim->zhida_mac, ETH_ALEN) != 0)
			continue;
		if (is_warmup_reply(shim, frame, (size_t)len))
			return;
		check_arp(shim, frame, (size_t)len);
	}
}

// The kernel's receive time of the frame recvmsg returned (SO_TIMESTAMP). packetdrill's
// clock in shared-object mode is shim_gettimeofday (run.c now_usecs), the same
// CLOCK_REALTIME, so a packet that arrives while packetdrill sleeps keeps its arrival time.
static long long receive_time(struct msghdr *msg)
{
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP) {
			struct timeval tv;
			memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
			return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
		}
	}
	die("received frame carries no SCM_TIMESTAMP");
}

static int shim_netdev_receive(void *userdata, void *buf, size_t *count,
			       long long *time_usecs)
{
	struct shim *shim = userdata;
	struct pollfd pfd = {.fd = shim->fd, .events = POLLIN};
	int ready = poll(&pfd, 1, RECEIVE_POLL_MS);
	if (ready < 0) {
		if (errno == EINTR)
			return -1;
		die_errno("poll");
	}
	if (ready == 0)
		return -1;

	unsigned char frame[MAX_FRAME];
	struct sockaddr_ll from;
	struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(struct timeval))];
	} control;
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.bytes,
		.msg_controllen = sizeof(control.bytes),
	};
	ssize_t len = recvmsg(shim->fd, &msg, MSG_TRUNC);
	if (len < 0)
		die_errno("recvmsg");
	if (from.sll_pkttype == PACKET_OUTGOING)
		return -1;
	if ((size_t)len > sizeof(frame)) {
		fprintf(stderr, "zhida_shim: %zd-byte frame exceeds the frame buffer\n", len);
		exit(1);
	}
	const struct ether_header *eth = (const struct ether_header *)frame;
	if ((size_t)len < sizeof(*eth))
		return -1;
	const unsigned char *payload = frame + sizeof(*eth);
	size_t payload_len = (size_t)len - sizeof(*eth);
	uint16_t type = ntohs(eth->ether_type);

	if (type == ETHERTYPE_ARP) {
		if (memcmp(eth->ether_shost, shim->zhida_mac, ETH_ALEN) == 0)
			check_arp(shim, frame, (size_t)len);
		return -1;
	}
	if (type != ETHERTYPE_IP || memcmp(eth->ether_dhost, shim->tester_mac, ETH_ALEN) != 0)
		return -1;
	if (payload_len > *count) {
		fprintf(stderr, "zhida_shim: %zu-byte IP packet exceeds packetdrill's buffer\n",
			payload_len);
		exit(1);
	}
	memcpy(buf, payload, payload_len);
	*count = payload_len;
	*time_usecs = receive_time(&msg);
	return 0;
}

static int shim_usleep(void *userdata, useconds_t usec)
{
	return usleep(usec);
}

static int shim_gettimeofday(void *userdata, struct timeval *tv, struct timezone *tz)
{
	return gettimeofday(tv, tz);
}

void packetdrill_interface_init(const char *flags, struct packetdrill_interface *ifc)
{
	check_cpu();
	struct shim *shim = calloc(1, sizeof(*shim));
	if (shim == NULL)
		die("out of memory");
	const char *iface = env("ZHIDA_IFACE");
	parse_mac("ZHIDA_MAC", shim->zhida_mac);
	parse_mac("TESTER_MAC", shim->tester_mac);
	parse_ip("ZHIDA_IP", &shim->zhida_ip);
	parse_ip("TESTER_IP", &shim->tester_ip);

	shim->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (shim->fd < 0)
		die_errno("socket(AF_PACKET)");
	int on = 1;
	if (setsockopt(shim->fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) < 0)
		die_errno("setsockopt(SO_TIMESTAMP)");
	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = wait_iface_up(shim->fd, iface),
	};
	if (bind(shim->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die_errno("bind(AF_PACKET)");
	warm_arp(shim);

	*ifc = (struct packetdrill_interface){
		.userdata = shim,
		.free = shim_free,
		.socket = unsupported_socket,
		.bind = unsupported_bind,
		.listen = unsupported_listen,
		.accept = unsupported_accept,
		.connect = unsupported_connect,
		.read = unsupported_read,
		.readv = unsupported_readv,
		.recv = unsupported_recv,
		.recvfrom = unsupported_recvfrom,
		.recvmsg = unsupported_recvmsg,
		.write = unsupported_write,
		.writev = unsupported_writev,
		.send = unsupported_send,
		.sendto = unsupported_sendto,
		.sendmsg = unsupported_sendmsg,
		.fcntl = unsupported_fcntl,
		.ioctl = unsupported_ioctl,
		.close = unsupported_close,
		.shutdown = unsupported_shutdown,
		.getsockopt = unsupported_getsockopt,
		.setsockopt = unsupported_setsockopt,
		.poll = unsupported_poll,
		.netdev_send = shim_netdev_send,
		.netdev_receive = shim_netdev_receive,
		.usleep = shim_usleep,
		.gettimeofday = shim_gettimeofday,
		.epoll_create = unsupported_epoll_create,
		.epoll_ctl = unsupported_epoll_ctl,
		.epoll_wait = unsupported_epoll_wait,
		.pipe = unsupported_pipe,
		.splice = unsupported_splice,
	};
}
