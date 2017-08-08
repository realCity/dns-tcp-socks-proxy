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
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <time.h>
#include <resolv.h>
#include <signal.h>
#include "coroutine_int.h"
#include "local_ns_parser.h"

static int SOCKS_PORT = 9050;
static char *SOCKS_ADDR = "127.0.0.1";
static int LISTEN_PORT = 53;
static char *LISTEN_ADDR = "0.0.0.0";

static FILE *LOG_FILE = NULL;
static char *RESOLVCONF = "resolv.conf";
static char *LOGFILE = "/dev/null";
static char *USERNAME = "nobody";
static char *GROUPNAME = "nobody";
static int NUM_DNS = 0;
static char **dns_servers = NULL;
static char *m_local_resolvconf = "/etc/resolv.conf";
static uint8_t m_daemonize = 1;
static uint8_t m_verbose = 0;

struct QueryContext {
	struct sockaddr_in client;
	Coroutine *co;
	QLIST_ENTRY(QueryContext) next;
	uint8_t *replydata;
	int fd;
	uint8_t events;
	uint8_t finish;
	uint16_t buflen;
	uint16_t fdidx;
	uint8_t buf[6];
};

static int m_listenfd = -1;
static QLIST_HEAD(, QueryContext) m_queries = QLIST_HEAD_INITIALIZER();

static inline void error_exit(const char *e) {
	perror(e);
	exit(EXIT_FAILURE);
}

static inline void get_time_str(char tmstr[22]) {
	struct tm t;
	struct timespec ts;
	size_t slen;

	memset(&t, 0, sizeof(t));
#ifdef CLOCK_REALTIME
	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		perror("get CLOCK_REALTIME error");
		memset(&ts, 0, sizeof(ts));
	}
#else
	memset(&ts, 0, sizeof(ts));
	ts.tv_sec = time(NULL);
#endif
	localtime_r(&ts.tv_sec, &t);
	tmstr[0] = '\0';
	slen = strftime(tmstr, 22, "%y-%m-%d %T", &t);

	if (slen > 0) {
		snprintf(tmstr + slen, 22 - slen, ".%03ld", ts.tv_nsec / 1000000);
	}
}

static inline uint8_t mylog_enable(void) {
	return LOG_FILE ? 1 : 0;
}

#define mylog(M, S...) _mylog(1, M, S)
#define mylog_s(M) _mylog(1, M)
static void _mylog(uint8_t newline, const char *message, ...) {
	int ret;
	va_list ap;
	char tmstr[22];
	if (!LOG_FILE) { return; }
	get_time_str(tmstr);
	if (fprintf(LOG_FILE, "%s: ", tmstr) < 0) {
		perror("write log file error");
	}
	va_start(ap, message);
	ret = vfprintf(LOG_FILE, message, ap);
	va_end(ap);
	if (ret < 0) {
		perror("write log file error");
	} else if (newline) {
		fputc('\n', LOG_FILE);
		fflush(LOG_FILE);
	}
}

static char *get_value(char *line) {
	char *token, *tmp;
	token = strtok(line, " ");
	for (;;) {
		if (!(tmp = strtok(NULL, " ")))
			break;
		else
			token = tmp;
	}
	return token;
}

static char *string_value(char *value) {
	char *tmp = strdup(value);
	if (!tmp)
		error_exit("[!] Out of memory");
	value = tmp;
	if (value[strlen(value) - 1] == '\n')
		value[strlen(value) - 1] = '\0';
	if (strcmp(value, "") == 0)
		return NULL;
	return value;
}

static void parse_config(const char *file) {
	char line[128];
	char *s;

	FILE *f = fopen(file, "r");
	if (!f) {
		fprintf(stderr, "[!] Error opening configuration file %s: %s\n", file, strerror(errno));
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

static void parse_resolv_conf() {
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

	while (fgets(ns, 80, f)) {
		if (!regexec(&preg, ns, 1, pmatch, 0)) NUM_DNS++;
	}
	if (NUM_DNS < 1) {
		fprintf(stderr, "[!] No name server in %s\n", RESOLVCONF);
		exit(EXIT_FAILURE);
	}

	dns_servers = calloc(NUM_DNS, sizeof(char *));
	if (!dns_servers)
		error_exit("[!] Out of memory");

	rewind(f);
	size_t slen;
	while (fgets(ns, 80, f)) {
		if (regexec(&preg, ns, 1, pmatch, 0)) continue;
		slen = strlen(ns);
		if (ns[slen - 1] == '\n')
			ns[slen - 1] = '\0';
		dns_servers[i] = malloc(slen + 1);
		if (!dns_servers[i])
			error_exit("[!] Out of memory");
		memcpy(dns_servers[i], ns, slen + 1);
		i++;
	}
	fclose(f);
	regfree(&preg);
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

static int tcp_query(struct QueryContext *qctx, const char *nameserver) {
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
		qctx->events = POLLOUT;
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
			qctx->events = POLLOUT;
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
			qctx->events = POLLIN;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}
	if (!datlen) {
		rc = ECONNRESET;
		goto out;
	} else if (datlen != 2 || tmp[0] != 5 || tmp[1]) {
		mylog_s("SOCKS5 handshake data error");
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
			qctx->events = POLLOUT;
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
			qctx->events = POLLIN;
			qemu_coroutine_yield();
		} else {
			break;
		}
	}
	if (!datlen) {
		rc = ECONNRESET;
		goto out;
	} else if (datlen != 10 || memcmp(tmp, "\x05\x00\x00\x01", 4)) {
		mylog_s("SOCKS5 reply data error");
		goto out;
	}

	// forward dns query
	*((uint16_t *) qctx->buf) = htons(qctx->buflen);
	for (;;) {
		if (send(sock, qctx->buf, qctx->buflen + 2, 0) < 0) {
			rc = errno;
			if (rc != EAGAIN) { goto out; }
			qctx->events = POLLOUT;
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
			qctx->events = POLLIN;
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
				mylog_s("Out of memory");
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

static char *hostname_buf = NULL;
static size_t hostname_buflen = 0;
static const char *hostname_from_question(ns_msg msg) {
	ns_rr rr;
	int rrnum, rrmax;
	const char *result;
	int result_len;
	rrmax = ns_msg_count(msg, ns_s_qd);
	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (local_ns_parserr(&msg, ns_s_qd, rrnum, &rr)) {
			result_len = errno;
			mylog("local_ns_parserr error: %d %s", result_len, strerror(result_len));
			return NULL;
		}
		result = ns_rr_name(rr);
		result_len = strlen(result) + 1;
		if (result_len > hostname_buflen) {
			hostname_buflen = result_len << 1;
			hostname_buf = realloc(hostname_buf, hostname_buflen);
			if (!hostname_buf) {
				mylog_s("Out of memory");
				exit(500);
			}
		}
		memcpy(hostname_buf, result, result_len);
		return hostname_buf;
	}
	return NULL;
}

static void log_question(const struct QueryContext *qctx) {
	int rc;
	ns_msg msg;
	const char *str;

	if (!mylog_enable()) return;

	if (local_ns_initparse(qctx->buf + 2, qctx->buflen, &msg) < 0) {
		rc = errno;
		mylog("local_ns_initparse error: %d %s", rc, strerror(rc));
		return;
	}

	str = hostname_from_question(msg);
	if (!str) str = "";
	mylog("request 0x%hX %s", ns_msg_id(msg), str);
}

static void log_answer(const struct QueryContext *qctx, int dnsidx) {
	int rc, rrmax, rrnum;
	ns_msg msg;
	const char *str;
	uint16_t dlen;
	ns_rr rr;
	uint8_t b = 0;

	if (!mylog_enable() || !qctx->replydata) return;

	dlen = ntohs(*((uint16_t *) qctx->replydata));
	if (local_ns_initparse(qctx->replydata + 2, dlen, &msg) < 0) {
		rc = errno;
		mylog("local_ns_initparse error: %d %s", rc, strerror(rc));
		return;
	}

	str = hostname_from_question(msg);
	if (!str) str = "";
	_mylog(0, "response 0x%hX %s from %s:53 - ", ns_msg_id(msg), str, dns_servers[dnsidx]);
	rrmax = ns_msg_count(msg, ns_s_an);

	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (local_ns_parserr(&msg, ns_s_an, rrnum, &rr)) {
			rc = errno;
			mylog("\nlocal_ns_parserr error: %d %s", rc, strerror(rc));
			continue;
		}
		if (ns_rr_type(rr) != ns_t_a) continue;
		if (b) {
			fputs(", ", LOG_FILE);
		} else {
			b = 1;
		}
		fputs(inet_ntoa(*(struct in_addr *) ns_rr_rdata(rr)), LOG_FILE);
	}

	fputc('\n', LOG_FILE);
	fflush(LOG_FILE);
}

static void query_thread(void *arg) {
	struct QueryContext *qctx = arg;
	static int m_cur_dns = 0;
	int start = m_cur_dns, i, rc;
	uint8_t b = 0;

	if (m_verbose) log_question(qctx);

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
			if (m_verbose) log_answer(qctx, i);
			break;
		}
	}

	qctx->finish = 1;
}

static inline void delete_job(struct QueryContext *qctx) {
	if (!qctx->finish) { qemu_coroutine_delete(qctx->co); }
	QLIST_REMOVE(qctx, next);
	if (qctx->fd >= 0) { tcpclose(qctx->fd); }
	if (qctx->replydata) { free(qctx->replydata); }
#ifdef _DEBUG
	printf("free QueryContext %p\n", qctx);
#endif
	free(qctx);
}

static void udp_listener() {
	struct sockaddr_in dns_listener, dns_client;
	socklen_t scklen;
	uint8_t recvbuf[1504], haswr;
	int rc, len, i;
	struct pollfd *fds;
	uint16_t maxfds = 16, dlen;
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

	if(m_local_resolvconf != NULL) {
		FILE *resolv = fopen(m_local_resolvconf, "w");
		if (!resolv) {
			fprintf(stderr, "[!] Error opening %s: %s\n", m_local_resolvconf, strerror(errno));
			mylog("Overwrote local resolv.conf: %s", m_local_resolvconf);
		} else {
			mylog("Overwrote local resolv.conf: %s", m_local_resolvconf);
			fprintf(resolv, "nameserver %s\n", strcmp(LISTEN_ADDR, "0.0.0.0") ? LISTEN_ADDR : "127.0.0.1");
			fclose(resolv);
		}
	}

	if (strcmp(LOGFILE, "/dev/null")) {
		LOG_FILE = fopen(LOGFILE, "a+");
		if (!LOG_FILE)
			error_exit("[!] Error opening logfile.");
	}

	if(USERNAME != NULL && GROUPNAME != NULL) {
		if (!getuid()) {
			struct group *grp = getgrnam(GROUPNAME);
			if (!grp) {
				fprintf(stderr, "[!] Group (%s) does not exist! Quiting\n", GROUPNAME);
				exit(EXIT_FAILURE);
			} else if (setgid(grp->gr_gid) < 0)
				fprintf(stderr, "setgid failed: %s\n", strerror(errno));

			struct passwd *usr = getpwnam(USERNAME);
			if (!usr) {
				fprintf(stderr, "[!] Username (%s) does not exist! Quiting\n", USERNAME);
				exit(EXIT_FAILURE);
			} else if (setuid(usr->pw_uid) < 0)
				fprintf(stderr, "setuid failed: %s\n", strerror(errno));
		} else {
			printf("[!] Only root can run as %s:%s\n", USERNAME, GROUPNAME);
				exit(EXIT_FAILURE);
		}
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

	fds = malloc(sizeof(*fds) * maxfds);
	if (!fds) {
		mylog_s("Out of memory");
		exit(500);
	}

	for (;;) {
		fds[0].fd = m_listenfd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		len = 1;
		haswr = 0;

		QLIST_FOREACH(qctx, &m_queries, next) {
			if (qctx->replydata) {
				haswr = 1;
			} else if (qctx->finish) {
				qctx2 = qctx;
				qctx = *qctx->next.le_prev;
				delete_job(qctx2);
				continue;
			}

			if (qctx->fd >= 0) {
				if (len >= maxfds) {
					fds = realloc(fds, sizeof(*fds) * maxfds * 2);
					if (!fds) {
						mylog_s("Out of memory");
						exit(500);
					}
					maxfds *= 2;
				}
				fds[len].fd = qctx->fd;
				fds[len].events = 0;
				fds[len].revents = 0;
				if (qctx->events & POLLIN) { fds[len].events |= POLLIN; }
				if (qctx->events & POLLOUT) { fds[len].events |= POLLOUT; }
				qctx->fdidx = len;
				len++;
			} else {
				qctx->fdidx = 0;
			}
		}

		if (haswr) { fds[0].events |= POLLOUT; }

		if (poll(fds, len, 3000) < 0) {
			rc = errno;
			mylog("poll error: %d %s", rc, strerror(rc));
			sleep(1);
			continue;
		}

		for (i = 0; i < len; i++) {
			if (!fds[i].revents) { continue; }
			if (fds[i].revents & (POLLERR | POLLHUP)) {
				if (!i) {
					mylog_s("Local listener error! Quiting");
					exit(400);
				}

				QLIST_FOREACH(qctx, &m_queries, next) {
					if (qctx->fdidx == (uint16_t) i) {
						qemu_coroutine_enter(qctx->co, qctx);
						break;
					}
				}
			} else if (fds[i].revents & POLLIN) {
				if (!i) {
					scklen = sizeof(dns_client);
					rc = recvfrom(m_listenfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &dns_client,
							&scklen);
					if (rc < 0) {
						rc = errno;
						mylog("recv DNS request error: %d %s", rc, strerror(rc));
					} else if (!rc || rc >= (int) sizeof(recvbuf)) {
						mylog("recv DNS request failed: length=%d", rc);
					} else {
						qctx = malloc(sizeof(*qctx) + rc);
						if (!qctx) {
							mylog_s("Out of memory");
							exit(500);
						}
#ifdef _DEBUG
						printf("malloc QueryContext %p\n", qctx);
#endif
						qctx->fd = -1;
						qctx->finish = 0;
						qctx->replydata = NULL;
						memcpy(&qctx->client, &dns_client, sizeof(dns_client));
						qctx->events = 0;
						qctx->fdidx = 0;
						qctx->buflen = rc;
						memcpy(qctx->buf + 2, recvbuf, rc);
						qctx->co = qemu_coroutine_create(query_thread);
						QLIST_INSERT_HEAD(&m_queries, qctx, next);
						qemu_coroutine_enter(qctx->co, qctx);
					}
					continue;
				}

				QLIST_FOREACH(qctx, &m_queries, next) {
					if (qctx->fdidx == (uint16_t) i) {
						qemu_coroutine_enter(qctx->co, qctx);
						break;
					}
				}
			} else if (fds[i].revents & POLLOUT) {
				if (!i) {
					QLIST_FOREACH(qctx, &m_queries, next) {
						if (!qctx->replydata) { continue; }
						dlen = ntohs(*((uint16_t *) qctx->replydata));
						rc = sendto(m_listenfd, qctx->replydata + 2, dlen, 0,
								(struct sockaddr *) &qctx->client, sizeof(qctx->client));
						if (rc < 0) {
							rc = errno;
							if (rc == EAGAIN) { break; }
							mylog("send DNS reply to client failed: %d %s", rc, strerror(rc));
						} else if ((uint16_t) rc != dlen) {
							mylog("send DNS reply to client failed: only send %d/%hu", rc, dlen);
						}
						free(qctx->replydata);
						qctx->replydata = NULL;
					}
					continue;
				}

				QLIST_FOREACH(qctx, &m_queries, next) {
					if (qctx->fdidx == (uint16_t) i) {
						qemu_coroutine_enter(qctx->co, qctx);
						break;
					}
				}
			}
		}	// end for
	}	// end for
}

static void set_signal_handlers(void) {
	struct sigaction sa;
	uint32_t i;
	int ignoresignal[] = {
		SIGQUIT,
	#ifdef SIGPIPE
		SIGPIPE,
	#endif
	#ifdef SIGTSTP
		SIGTSTP,
	#endif
	#ifdef SIGTTIN
		SIGTTIN,
	#endif
	#ifdef SIGTTOU
		SIGTTOU,
	#endif
	#ifdef SIGINFO
		SIGINFO,
	#endif
	#ifdef SIGUSR1
		SIGUSR1,
	#endif
	#ifdef SIGUSR2
		SIGUSR2,
	#endif
	#ifdef SIGCHLD
		SIGCHLD,
	#endif
	#ifdef SIGCLD
		SIGCLD,
	#endif
		-1
	};

	memset(&sa, 0, sizeof(sa));
#ifdef SA_RESTART
	sa.sa_flags = SA_RESTART;
#else
	sa.sa_flags = 0;
#endif
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = SIG_IGN;
	for (i = 0; ignoresignal[i] > 0; i++) {
		sigaction(ignoresignal[i], &sa, NULL);
	}
}

static void usage(char *argv[]) {
	printf("Usage: %s [options]\n", argv[0]);
	printf(" * With no parameters, the configuration file is read from 'dns_proxy.conf'.\n\n");
	printf(" -n          -- No configuration file (socks: 127.0.0.1:9999, listener: 0.0.0.0:53).\n");
	printf(" -h          -- Print this message and exit.\n");
	printf(" -c file     -- Read from specified configuration file.\n");
	printf(" -f          -- Run in foreground.\n");
	printf(" -v          -- verbose logging.\n\n");
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
}

int main(int argc, char *argv[]) {
	if (argc == 1)
		parse_config("dns_proxy.conf");
	else if (argc >= 2) {
		uint8_t foreground = 0;
		int ch;
		while ((ch = getopt(argc, argv, "hnfc:v")) != -1) {
			switch (ch) {
			case 'h':
				usage(argv);
				exit(0);
			case 'n':
				break;
			case 'f':
				foreground = 1;
				break;
			case 'c':
				parse_config(optarg);
				break;
			case 'v':
				m_verbose = 1;
				break;
			default:
				usage(argv);
				exit(1);
			}
		}
		argc -= optind;
		argv += optind;
		if (foreground) { m_daemonize = 0; }
	}

	printf("[*] Listening on: %s:%d\n", LISTEN_ADDR, LISTEN_PORT);
	printf("[*] Using SOCKS proxy: %s:%d\n", SOCKS_ADDR, SOCKS_PORT);
	if(USERNAME != NULL && GROUPNAME != NULL)
		printf("[*] Will drop priviledges to %s:%s\n", USERNAME, GROUPNAME);
	else {
		struct group *grp = getgrgid(getgid());
		struct passwd *pwd = getpwuid(getuid());
		const char *username = NULL;
		const char *groupname = NULL;
		char groupname_buf[100] = "";
		char username_buf[100] = "";

		if(grp == NULL) {
			int ret = snprintf(groupname_buf, 100, "%i", getgid());
			groupname = ret > 0 && ret < 100 ? groupname_buf : "?";
		} else {
			groupname = grp->gr_name;
		}

		if(pwd == NULL) {
			int ret = snprintf(username_buf, 100, "%i", getuid());
			username = ret > 0 && ret < 100 ? username_buf : "?";
		} else {
			username = pwd->pw_name;
		}

		printf("[*] Keeping existing priviledges as %s:%s\n", username, groupname);
	}
	parse_resolv_conf();
	printf("[*] Loaded %d DNS servers from %s.\n\n", NUM_DNS, RESOLVCONF);

	set_signal_handlers();
	// start the dns proxy
	udp_listener();
	exit(EXIT_SUCCESS);
}
