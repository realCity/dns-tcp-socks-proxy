/*
 *  UDP-TCP SOCKS DNS Tunnel
 *  (C) 2012 jtRIPper
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include "coroutine_int.h"

int SOCKS_PORT = 9050;
char *SOCKS_ADDR = "127.0.0.1";
int LISTEN_PORT = 53;
char *LISTEN_ADDR = "0.0.0.0";

FILE *LOG_FILE = NULL;
char *RESOLVCONF = "resolv.conf";
char *LOGFILE = "/dev/null";
char *USERNAME = "nobody";
char *GROUPNAME = "nobody";
int NUM_DNS = 0;
char **dns_servers = NULL;
static char *m_local_resolvconf = "/etc/resolv.conf";
static uint8_t m_daemonize = 1;

#define FDIN  1
#define FDOUT 2

struct QueryContext {
	struct sockaddr_in client;
	Coroutine *co;
	QLIST_ENTRY(QueryContext) next;
	uint8_t *replydata;
	int fd;
	uint8_t events;
	uint8_t finish;
	uint16_t buflen;
	uint8_t buf[8];
};

static int m_listenfd = -1;
static QLIST_HEAD(, QueryContext) m_queries = QLIST_HEAD_INITIALIZER();

static inline void error_exit(const char *e) {
	perror(e);
	exit(EXIT_FAILURE);
}

void mylog(const char *message, ...) {
	if (!LOG_FILE) { return; }

	va_list ap;
	va_start(ap, message);
	int ret = vfprintf(LOG_FILE, message, ap);
	va_end(ap);
	if (ret < 0) {
		fprintf(stderr, "write log file error\n");
	} else {
		fputc('\n', LOG_FILE);
		fflush(LOG_FILE);
	}
}

char *get_value(char *line) {
	char *token, *tmp;
	token = strtok(line, " ");
	for (;;) {
		if ((tmp = strtok(NULL, " ")) == NULL)
			break;
		else
			token = tmp;
	}
	return token;
}

char *string_value(char *value) {
	char *tmp = strdup(value);
	if (!tmp) {
		error_exit("[!] Out of memory");
	}
	value = tmp;
	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	return value;
}

void parse_config(char *file) {
	char line[128];
	char *s;

	FILE *f = fopen(file, "r");
	if (!f) {
		fprintf(stderr, "[!] Error opening configuration file %s: %s", file, strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), f)) {
		s = line;
		while (isspace(*s)) { s++; }
		if (s[0] == '\0' || s[0] == '#') { continue; }

		if (!strncmp(s, "socks_port", 10))
			SOCKS_PORT = strtol(get_value(s), NULL, 10);
		else if (!strncmp(s, "socks_addr", 10))
			SOCKS_ADDR = string_value(get_value(s));
		else if (!strncmp(s, "listen_addr", 11))
			LISTEN_ADDR = string_value(get_value(s));
		else if (!strncmp(s, "listen_port", 11))
			LISTEN_PORT = strtol(get_value(s), NULL, 10);
		else if (!strncmp(s, "set_user", 8))
			USERNAME = string_value(get_value(s));
		else if (!strncmp(s, "set_group", 9))
			GROUPNAME = string_value(get_value(s));
		else if (!strncmp(s, "resolv_conf", 11))
			RESOLVCONF = string_value(get_value(s));
		else if (!strncmp(s, "log_file", 8))
			LOGFILE = string_value(get_value(s));
		else if (!strncmp(s, "local_resolv_conf", 17))
			m_local_resolvconf = string_value(get_value(s));
		else if (!strncmp(s, "foreground", 10))
			m_daemonize = !strtol(get_value(s), NULL, 10);
	}

	fclose(f);
}

void parse_resolv_conf() {
	char ns[80];
	int i = 0;
	regex_t preg;
	regmatch_t pmatch[1];
	regcomp(&preg, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n?$", REG_EXTENDED);

	FILE *f = fopen(RESOLVCONF, "r");
	if (!f) {
		fprintf(stderr, "[!] Error opening %s: %s\n", RESOLVCONF, strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (fgets(ns, 80, f) != NULL) {
		if (!regexec(&preg, ns, 1, pmatch, 0))
			NUM_DNS++;
	}
	if (NUM_DNS < 1) {
		fprintf(stderr, "[!] No name server in %s\n", RESOLVCONF);
		exit(EXIT_FAILURE);
	}

	dns_servers = calloc(NUM_DNS, sizeof(char *));
	if (!dns_servers) {
		error_exit("[!] Out of memory");
	}

	rewind(f);
	size_t slen;
	while (fgets(ns, 80, f) != NULL) {
		if (regexec(&preg, ns, 1, pmatch, 0) != 0)
			continue;
		slen = strlen(ns);
		if (ns[slen - 1] == '\n') {
			ns[slen - 1] = '\0';
		}
		dns_servers[i] = malloc(slen + 1);
		if (!dns_servers[i]) {
			error_exit("[!] Out of memory");
		}
		memcpy(dns_servers[i], ns, slen + 1);
		i++;
	}
	fclose(f);
}

static inline int tcpnodelay(int sock) {
	int yes = 1;
	return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int));
}

static inline int socknonblock(int sock) {
#ifdef O_NONBLOCK
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
	int yes = 1;
	return ioctl(sock, FIONBIO, &yes);
#endif
}

static inline int tcpclose(int sock) {
	shutdown(sock, SHUT_WR);
	return close(sock);
}

int tcp_query(struct QueryContext *qctx, const char *nameserver) {
	int sock, rc = -1, datlen;
	uint16_t sl;
	socklen_t scklen;
	struct sockaddr_in socks_server;
	char tmp[1504];

	memset(&socks_server, 0, sizeof(socks_server));
	socks_server.sin_family = AF_INET;
	socks_server.sin_port = htons(SOCKS_PORT);
	socks_server.sin_addr.s_addr = inet_addr(SOCKS_ADDR);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) { return errno; }
	qctx->fd = sock;

	if (socknonblock(sock) < 0) {
		rc = errno;
		mylog("Set non-blocking failed: %d %s", rc, strerror(rc));
	}
	if (tcpnodelay(sock) < 0) {
		rc = errno;
		mylog("Set no delay failed: %d %s", rc, strerror(rc));
	}

	if (connect(sock, (struct sockaddr *) &socks_server, sizeof(socks_server)) < 0) {
		rc = errno;
		if (rc != EINPROGRESS) { goto out; }
		qctx->events = FDOUT;
		qemu_coroutine_yield();
	}
	datlen = 0;
	scklen = sizeof(datlen);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &datlen, &scklen) < 0) {
		rc = errno;
		goto out;
	} else if (datlen) {
		rc = datlen;
		goto out;
	}

	// socks handshake
	for (;;) {
		if (send(sock, "\x05\x01\x00", 3, 0) < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDOUT;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}

	for (;;) {
		datlen = recv(sock, tmp, sizeof(tmp), 0);
		if (datlen < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDIN;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}
	if (!datlen) {
		rc = ECONNRESET;
		goto out;
	} else if (datlen != 2 || tmp[0] != 5 || tmp[1]) {
		mylog("SOCKS5 handshake data error");
		goto out;
	}

	in_addr_t remote_dns = inet_addr(nameserver);
	memcpy(tmp, "\x05\x01\x00\x01", 4);
	memcpy(tmp + 4, &remote_dns, 4);
	memcpy(tmp + 8, "\x00\x35", 2);

#ifdef _DEBUG
	mylog("Using DNS %s (%X)", nameserver, remote_dns);
#endif

	for (;;) {
		if (send(sock, tmp, 10, 0) < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDOUT;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}

	for (;;) {
		datlen = recv(sock, tmp, sizeof(tmp), 0);	// 05 00 00 01 00 00 00 00 00 00
		if (datlen < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDIN;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}
	if (!datlen) {
		rc = ECONNRESET;
		goto out;
	} else if (datlen != 10 || memcmp(tmp, "\x05\x00\x00\x01", 4)) {
		mylog("SOCKS5 reply data error");
		goto out;
	}

	// forward dns query
	*((uint16_t *) qctx->buf) = htons(qctx->buflen);
	for (;;) {
		if (send(sock, qctx->buf, qctx->buflen + 2, 0) < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDOUT;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}

	for (;;) {
		datlen = recv(sock, tmp, sizeof(tmp), 0);
		if (datlen < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = FDIN;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}
	if (!datlen) {
		rc = ECONNRESET;
		goto out;
	} else if (datlen < 2 || datlen >= (int) sizeof(tmp)) {
		mylog("SOCKS5 reply data length error: %d", datlen);
		goto out;
	} else {
		sl = ntohs(*((uint16_t *) tmp));
		if (sl != datlen - 2) {
			mylog("SOCKS5 reply data length error: %hu/%d", sl, datlen - 2);
		} else {
			qctx->replydata = malloc(datlen);
			if (!qctx->replydata) {
				mylog("Out of memory");
				exit(500);
			} else {
				memcpy(qctx->replydata, tmp, datlen);
			}
		}
		rc = 0;
	}

out:
	tcpclose(sock);
	qctx->events = 0;
	qctx->fd = -1;
	return rc;
}

static void query_thread(void *arg) {
	struct QueryContext *qctx = arg;
	static int m_cur_dns = 0;
	int start = m_cur_dns, i, rc;
	uint8_t b = 0;

	for (i = start;; i++) {
		if (i >= NUM_DNS) { i = 0; }
		if (b) {
			if (i == start) { break; }
		} else {
			b = 1;
		}
		rc = tcp_query(qctx, dns_servers[i]);
		if (rc) {
			mylog("tcp_query DNS %s failed: %d %s", dns_servers[i], rc,
					rc < 0 ? "Bad data from SOCKS5 server" : strerror(rc));
			if (rc == ECONNREFUSED) { break; }
		} else {
			m_cur_dns = i;
			break;
		}
	}

	qctx->finish = 1;
}

static void udp_listener() {
	struct sockaddr_in dns_listener, dns_client;
	socklen_t scklen;
	uint8_t recvbuf[1504], haswr, haserr;
	int rc, len, max_fd;
	fd_set rdset, wrset, errset;
	struct timeval timeout;
	struct QueryContext *qctx, *qctx2;

	memset(&dns_listener, 0, sizeof(dns_listener));
	dns_listener.sin_family = AF_INET;
	dns_listener.sin_port = htons(LISTEN_PORT);
	dns_listener.sin_addr.s_addr = inet_addr(LISTEN_ADDR);

	// create our udp listener
	m_listenfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (m_listenfd < 0)
		error_exit("[!] Error setting up dns proxy");
	else if (socknonblock(m_listenfd) < 0)
		error_exit("[!] Error set non-blocking");
	else if (bind(m_listenfd, (struct sockaddr *) &dns_listener, sizeof(dns_listener)) < 0)
		error_exit("[!] Error binding on dns proxy");

	FILE *resolv = fopen(m_local_resolvconf, "w");
	if (!resolv)
		fprintf(stderr, "[!] Error opening %s: %s\n", m_local_resolvconf, strerror(errno));
	else {
		fprintf(resolv, "nameserver %s\n", strcmp(LISTEN_ADDR, "0.0.0.0") ? LISTEN_ADDR : "127.0.0.1");
		fclose(resolv);
	}

	if (strcmp(LOGFILE, "/dev/null")) {
		LOG_FILE = fopen(LOGFILE, "a+");
		if (!LOG_FILE)
			error_exit("[!] Error opening logfile.");
	}

	if (!getuid()) {
		if (setgid(getgrnam(GROUPNAME)->gr_gid) < 0)
			fprintf(stderr, "setgid failed: %s\n", strerror(errno));
		if (setuid(getpwnam(USERNAME)->pw_uid) < 0)
			fprintf(stderr, "setuid failed: %s\n", strerror(errno));
	} else {
		printf("[!] Only root can run as %s:%s\n", USERNAME, GROUPNAME);
	}

	// daemonize the process.
	if (m_daemonize) {
		printf("[*] Backgrounding process.\n");

		close(STDIN_FILENO);
		if (open("/dev/null", O_RDWR, 0) != STDIN_FILENO) { fprintf(stderr, "Can't set stdin\n"); }
		close(STDOUT_FILENO);
		if (dup(STDIN_FILENO) != STDOUT_FILENO) { fprintf(stderr, "Can't set stdout\n"); }
		close(STDERR_FILENO);
		if (dup(STDIN_FILENO) != STDERR_FILENO) { fprintf(stderr, "Can't set stderr\n"); }

		if (fork() != 0) { exit(0); }
		if (fork() != 0) { exit(0); }
	} else {
		printf("[*] Run in foreground.\n");
	}

	for (;;) {
		FD_ZERO(&rdset);
		FD_ZERO(&wrset);
		FD_ZERO(&errset);

		FD_SET(m_listenfd, &rdset);
		max_fd = m_listenfd;
		haswr = 0;

		QLIST_FOREACH(qctx, &m_queries, next) {
			if (qctx->fd >= 0) {
				if (qctx->events & FDIN) { FD_SET(qctx->fd, &rdset); }
				if (qctx->events & FDOUT) { FD_SET(qctx->fd, &wrset); }
				FD_SET(qctx->fd, &errset);
				if (qctx->fd > max_fd) { max_fd = qctx->fd; }
			}
			if (qctx->replydata) { haswr = 1; }
		}
		if (haswr) { FD_SET(m_listenfd, &wrset); }

		timeout.tv_sec = 3;
		timeout.tv_usec = 0;

		if (select(max_fd + 1, &rdset, &wrset, &errset, &timeout) < 0) {
			rc = errno;
			mylog("select FDs error: %d %s", rc, strerror(rc));
			sleep(1);
			continue;
		}

		if (FD_ISSET(m_listenfd, &rdset)) {
			scklen = sizeof(dns_client);
			len = recvfrom(m_listenfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &dns_client, &scklen);
			if (len < 0) {
				rc = errno;
				mylog("recv DNS request error: %d %s", rc, strerror(rc));
			} else if (!len || len >= (int) sizeof(recvbuf)) {
				mylog("recv DNS request failed: length=%d", len);
			} else {
				qctx = malloc(sizeof(*qctx) + len);
				if (!qctx) {
					mylog("Out of memory");
					exit(500);
				}
				qctx->fd = -1;
				qctx->finish = 0;
				qctx->replydata = NULL;
				memcpy(&qctx->client, &dns_client, sizeof(dns_client));
				qctx->events = 0;
				qctx->buflen = len;
				memcpy(qctx->buf + 2, recvbuf, len);
				qctx->co = qemu_coroutine_create(query_thread);
				QLIST_INSERT_HEAD(&m_queries, qctx, next);
				qemu_coroutine_enter(qctx->co, qctx);
			}
		} else if (haswr && FD_ISSET(m_listenfd, &wrset)) {
			QLIST_FOREACH(qctx, &m_queries, next) {
				if (!qctx->replydata) { continue; }
				len = ntohs(*((uint16_t *) qctx->replydata));
				rc = sendto(m_listenfd, qctx->replydata + 2, len, 0, (struct sockaddr *) &qctx->client,
						sizeof(qctx->client));
				if (rc < 0) {
					rc = errno;
					if (rc == EAGAIN) { break; }
					mylog("send DNS reply to client failed: %d %s", rc, strerror(rc));
				} else if (rc != len) {
					mylog("send DNS reply to client failed: only send %d/%d", rc, len);
				}
				free(qctx->replydata);
				qctx->replydata = NULL;
			}
		}

		QLIST_FOREACH(qctx, &m_queries, next) {
			haserr = (qctx->fd >= 0 && FD_ISSET(qctx->fd, &errset));

			if (haserr || (qctx->finish && !qctx->replydata)) {
				qctx2 = qctx;
				qctx = *qctx->next.le_prev;
				if (!qctx2->finish) { qemu_coroutine_delete(qctx2->co); }
				QLIST_REMOVE(qctx2, next);
				if (haserr) {
					scklen = sizeof(rc);
					if (getsockopt(qctx2->fd, SOL_SOCKET, SO_ERROR, &rc, &scklen) < 0) {
						rc = errno;
						mylog("getsockopt failed: %d %s", rc, strerror(rc));
					} else {
						mylog("sock error: %d %s", rc, strerror(rc));
					}
				}
				if (qctx2->fd >= 0) { tcpclose(qctx2->fd); }
				if (qctx2->replydata) { free(qctx2->replydata); }
				free(qctx2);
				continue;
			}

			if (qctx->fd >= 0 && (FD_ISSET(qctx->fd, &rdset) || FD_ISSET(qctx->fd, &wrset)))
				qemu_coroutine_enter(qctx->co, qctx);
		}
	}
}

int main(int argc, char *argv[]) {
	if (argc == 1)
		parse_config("dns_proxy.conf");
	else if (argc == 2) {
		if (!strcmp(argv[1], "-h")) {
			printf("Usage: %s [options]\n", argv[0]);
			printf(" * With no parameters, the configuration file is read from 'dns_proxy.conf'.\n\n");
			printf(" -n          -- No configuration file (socks: 127.0.0.1:9999, listener: 0.0.0.0:53).\n");
			printf(" -h          -- Print this message and exit.\n");
			printf(" config_file -- Read from specified configuration file.\n\n");
			printf(" * The configuration file should contain any of the following options (and ignores lines that begin with '#'):\n");
			printf("   * socks_addr  -- socks listener address\n");
			printf("   * socks_port  -- socks listener port\n");
			printf("   * listen_addr -- address for the dns proxy to listen on\n");
			printf("   * listen_port -- port for the dns proxy to listen on (most cases 53)\n");
			printf("   * set_user    -- username to drop to after binding\n");
			printf("   * set_group   -- group to drop to after binding\n");
			printf("   * resolv_conf -- location of resolv.conf to read from\n");
			printf("   * log_file    -- location to log server IPs to. (only necessary for debugging)\n\n");
			printf(" * Configuration directives should be of the format:\n");
			printf("   option = value\n\n");
			printf(" * Any non-specified options will be set to their defaults:\n");
			printf("   * socks_addr   = 127.0.0.1\n");
			printf("   * socks_port   = 9050\n");
			printf("   * listen_addr  = 0.0.0.0\n");
			printf("   * listen_port  = 53\n");
			printf("   * set_user     = nobody\n");
			printf("   * set_group    = nobody\n");
			printf("   * resolv_conf  = resolv.conf\n");
			printf("   * log_file     = /dev/null\n");
			printf("   * local_resolv_conf = /etc/resolv.conf\n");
			exit(0);
		} else {
			parse_config(argv[1]);
		}
	}

	printf("[*] Listening on: %s:%d\n", LISTEN_ADDR, LISTEN_PORT);
	printf("[*] Using SOCKS proxy: %s:%d\n", SOCKS_ADDR, SOCKS_PORT);
	printf("[*] Will drop priviledges to %s:%s\n", USERNAME, GROUPNAME);
	parse_resolv_conf();
	printf("[*] Loaded %d DNS servers from %s.\n\n", NUM_DNS, RESOLVCONF);

	if (!getpwnam(USERNAME)) {
		printf("[!] Username (%s) does not exist! Quiting\n", USERNAME);
		exit(EXIT_FAILURE);
	}
	if (!getgrnam(GROUPNAME)) {
		printf("[!] Group (%s) does not exist! Quiting\n", GROUPNAME);
		exit(EXIT_FAILURE);
	}

	// start the dns proxy
	udp_listener();
	exit(EXIT_SUCCESS);
}
