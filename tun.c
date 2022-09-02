#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MTU 1500

void
usage(void)
{
	errx(EXIT_FAILURE, "tun [-hv] /dev/tun0 /dev/tun1");
}

int
main(int argc, char *argv[])
{
	int		ch, verbose = 0;;
	struct pollfd	fds[2];

	while ((ch = getopt(argc, argv, "h")) != -1) {
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
		int	 ifd = -1;
		int	 ofd = -1;
		char	*itun = NULL;
		char	*otun = NULL;

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

		struct {
			int family;
			char buf[MTU];
		} packet;

		ssize_t size = read(ifd, &packet, sizeof packet);
		if (size == -1)
			errx(EXIT_FAILURE, "%s", itun);

		struct ip *ip = (struct ip *)packet.buf;

		if (verbose) {
			printf("%s: size: %zu family: %u", itun, size,
			    ntohl(packet.family));
			printf(" ver: %u hlen: %u tlen: %u\n",
			    ip->ip_v,
			    ip->ip_hl << 2,
			    ntohs(ip->ip_len));
		}

		if (write(ofd, &packet, size) != size)
			err(EXIT_FAILURE, "%s", otun);
	}

	if (close(fds[0].fd) == -1)
		err(EXIT_FAILURE, "%s", tun0);
	if (close(fds[1].fd) == -1)
		err(EXIT_FAILURE, "%s", tun1);

	return EXIT_SUCCESS;
}
