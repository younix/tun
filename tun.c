#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MTU 1500

struct packet {
	int family;
	char buf[MTU];
};

int	 ifd;
int	 ofd;
char	*itun;
char	*otun;

bool
print(struct packet *p, size_t *size, struct ip *ip4, struct ip6_hdr *ip6,
    struct tcphdr *tcp, struct udphdr *udp)
{
	int sport = 0;
	int dport = 0;

	if (tcp) {
		sport = tcp->th_sport;
		dport = tcp->th_dport;
	}

	if (udp) {
		sport = udp->uh_sport;
		dport = udp->uh_dport;
	}

	if (ip4) {
		printf("%s:%u -> %s:%u\n", inet_ntoa(ip4->ip_src), sport,
		    inet_ntoa(ip4->ip_dst), dport);
	}

	return true;
}

void
forwarding(struct packet *packet, size_t size) {
	if (write(ofd, packet, size) != size)
		err(EXIT_FAILURE, "%s", otun);
}

void
usage(void)
{
	errx(EXIT_FAILURE, "tun [-hv] /dev/tun0 /dev/tun1");
}

int
main(int argc, char *argv[])
{
	int		ch;
	int		verbose = 0;
	struct pollfd	fds[2];
	bool		forward = true;

	while ((ch = getopt(argc, argv, "vh")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		case 'h':
		default:	
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	char *tun0 = argv[0];
	char *tun1 = argv[1];

	if ((fds[0].fd = open(tun0, O_RDWR)) == -1)
		err(EXIT_FAILURE, "%s", tun0);
	if ((fds[1].fd = open(tun1, O_RDWR)) == -1)
		err(EXIT_FAILURE, "%s", tun1);

	fds[0].events = fds[1].events = POLLIN;

	for (;;) {
		ifd = ofd = -1;
		itun = otun = NULL;

		int nready = poll(fds, 2, INFTIM);
		if (nready == -1)
			err(EXIT_FAILURE, "poll");
		if (nready == 0)
			errx(EXIT_FAILURE, "poll: timeout");

		if ((fds[0].revents & (POLLERR|POLLNVAL)))
			errx(EXIT_FAILURE, "%s", tun0);
		if ((fds[1].revents & (POLLERR|POLLNVAL)))
			errx(EXIT_FAILURE, "%s", tun1);

		/* local */
		if ((fds[0].revents & (POLLIN|POLLHUP))) {
			ifd = fds[0].fd;
			ofd = fds[1].fd;
			itun = tun0;
			otun = tun1;
		}
		/* remote */
		if ((fds[1].revents & (POLLIN|POLLHUP))) {
			ifd = fds[1].fd;
			ofd = fds[0].fd;
			itun = tun1;
			otun = tun0;
		}

		struct packet packet;

		ssize_t size = read(ifd, &packet, sizeof packet);
		if (size == -1)
			errx(EXIT_FAILURE, "%s", itun);

		struct ip	*ip4 = NULL;
		struct ip6_hdr	*ip6 = NULL;
		struct tcphdr	*tcp = NULL;
		struct udphdr	*udp = NULL;

		if (ntohl(packet.family) == AF_INET) {
			ip4 = (struct ip *)packet.buf;
			if (ip4->ip_p == IPPROTO_TCP)
				tcp = (struct tcphdr *)(packet.buf + (ip4->ip_hl << 2));
			if (ip4->ip_p == IPPROTO_UDP)
				udp = (struct udphdr *)(packet.buf + (ip4->ip_hl << 2));
		} else if (ntohl(packet.family) == AF_INET6) {
			ip6 = (struct ip6_hdr *)packet.buf;
			if (ip6->ip6_nxt == IPPROTO_TCP)
				tcp = (struct tcphdr *)(packet.buf + sizeof(*ip6));
			if (ip6->ip6_nxt == IPPROTO_UDP)
				udp = (struct udphdr *)(packet.buf + sizeof(*ip6));
		}

		if (verbose)
			forward = print(&packet, &size, ip4, ip6, tcp, udp);

		if (forward)
			forwarding(&packet, size);
	}

	if (close(fds[0].fd) == -1)
		err(EXIT_FAILURE, "%s", tun0);
	if (close(fds[1].fd) == -1)
		err(EXIT_FAILURE, "%s", tun1);

	return EXIT_SUCCESS;
}
