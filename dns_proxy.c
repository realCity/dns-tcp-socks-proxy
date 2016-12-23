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
#include <pthread.h>
#include <stdarg.h>

int   SOCKS_PORT  = 9050;
char *SOCKS_ADDR  = "127.0.0.1";
int   LISTEN_PORT = 53;
char *LISTEN_ADDR = "0.0.0.0";

FILE *LOG_FILE = NULL;
char *RESOLVCONF = "resolv.conf";
char *LOGFILE = "/dev/null";
char *USERNAME = "nobody";
char *GROUPNAME = "nobody";
int NUM_DNS = 0;
static int m_cur_dns = 0;
char **dns_servers = NULL;
static char *m_local_resolvconf = "/etc/resolv.conf";
static uint8_t m_daemonize = 1;
static pthread_mutex_t m_log_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
  char *buffer;
  int length;
} response;

typedef struct {
	response resp;
	int sock;
	struct sockaddr_in client;
} queryargs;

void error(char *e) {
  perror(e);
  exit(1);
}

void mylog(const char *message, ...) {
	if (!LOG_FILE) { return; }

	pthread_mutex_lock(&m_log_mutex);
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
	pthread_mutex_unlock(&m_log_mutex);
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
  if (!tmp) { error("[!] Out of memory"); }
  value = tmp;
  if (value[strlen(value)-1] == '\n')
    value[strlen(value)-1] = '\0';
  return value;
}

void parse_config(char *file) {
  char line[128];
  char *s;

  FILE *f = fopen(file, "r");
  if (!f) {
	  fprintf(stderr, "[!] Error opening configuration file %s: %s", file, strerror(errno));
	  exit(1);
  }

  while (fgets(line, sizeof(line), f)) {
    s = line;
    while (isspace(*s)) s++;
    if (s[0] == '\0' || s[0] == '#') continue;

    if(!strncmp(s, "socks_port", 10))
      SOCKS_PORT = strtol(get_value(s), NULL, 10);
    else if(!strncmp(s, "socks_addr", 10))
      SOCKS_ADDR = string_value(get_value(s));
    else if(!strncmp(s, "listen_addr", 11))
      LISTEN_ADDR = string_value(get_value(s));
    else if(!strncmp(s, "listen_port", 11))
      LISTEN_PORT = strtol(get_value(s), NULL, 10);
    else if(!strncmp(s, "set_user", 8))
      USERNAME = string_value(get_value(s));
    else if(!strncmp(s, "set_group", 9))
      GROUPNAME = string_value(get_value(s));
    else if(!strncmp(s, "resolv_conf", 11))
      RESOLVCONF = string_value(get_value(s));
    else if(!strncmp(s, "log_file", 8))
      LOGFILE = string_value(get_value(s));
    else if(!strncmp(s, "local_resolv_conf", 17))
      m_local_resolvconf = string_value(get_value(s));
    else if(!strncmp(s, "foreground", 10))
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
	  exit(1);
  }

  while (fgets(ns, 80, f) != NULL) {
    if (!regexec(&preg, ns, 1, pmatch, 0))
      NUM_DNS++;
  }
  if (NUM_DNS < 1) {
	  fprintf(stderr, "[!] No name server in %s\n", RESOLVCONF);
	  exit(1);
  }

  dns_servers = calloc(NUM_DNS, sizeof(char *));
  if (!dns_servers) { error("[!] Out of memory"); }

  rewind(f);
  size_t slen;
  while (fgets(ns, 80, f) != NULL) {
    if (regexec(&preg, ns, 1, pmatch, 0) != 0)
      continue;
    slen = strlen(ns);
    if (ns[slen - 1] == '\n') { ns[slen - 1] = '\0'; }
    dns_servers[i] = malloc(slen + 1);
    if (!dns_servers[i]) { error("[!] Out of memory"); }
    memcpy(dns_servers[i], ns, slen + 1);
    i++;
  }
  fclose(f);
}

int tcp_query(void *query, response *buffer, int len, const char *nameserver) {
  int sock, rc = -1;
  struct sockaddr_in socks_server;
  char tmp[1024];

  memset(&socks_server, 0, sizeof(socks_server));
  socks_server.sin_family = AF_INET;
  socks_server.sin_port = htons(SOCKS_PORT);
  socks_server.sin_addr.s_addr = inet_addr(SOCKS_ADDR);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) return errno;

  if (connect(sock, (struct sockaddr*)&socks_server, sizeof(socks_server)) < 0) {
	  rc = errno;
	  goto out;
  }

  // socks handshake
  if (send(sock, "\x05\x01\x00", 3, 0) < 0) {
	  rc = errno;
	  goto out;
  }

  int datlen = recv(sock, tmp, 1024, 0);
  if (datlen < 0) {
	  rc = errno;
	  goto out;
  } else if (!datlen) {
	  goto out;
  } else if (datlen != 2 || tmp[0] != 5 || tmp[1]) {
	  mylog("SOCKS v5 handshake data error");
	  goto out;
  }

  in_addr_t remote_dns = inet_addr(nameserver);
  memcpy(tmp, "\x05\x01\x00\x01", 4);
  memcpy(tmp + 4, &remote_dns, 4);
  memcpy(tmp + 8, "\x00\x35", 2);

  mylog("Using DNS server: %s (%X)", nameserver, remote_dns);

  if (send(sock, tmp, 10, 0) < 0) {
	  rc = errno;
	  goto out;
  }
  datlen = recv(sock, tmp, 1024, 0);	// 05 00 00 01 00 00 00 00 00 00
  if (datlen < 0) {
	  rc = errno;
	  goto out;
  } else if (!datlen) {
	  goto out;
  } else if (datlen != 10 || memcmp(tmp, "\x05\x00\x00\x01", 4)) {
	  mylog("SOCKS v5 response data error");
	  goto out;
  }

  // forward dns query
  if (send(sock, query, len, 0) < 0) {
	  rc = errno;
	  goto out;
  }
  buffer->length = recv(sock, buffer->buffer, 2048, 0);
  if (buffer->length < 0) {
	  rc = errno;
  } else {
	  rc = 0;
  }

out:
  shutdown(sock, SHUT_WR);
  close(sock);
  return rc;
}

static void *query_thread(void *arg) {
	queryargs *qa = (queryargs *) arg;
	int start = m_cur_dns, i, rc;
	uint8_t b = 0;
	response buffer;

	buffer.length = 2048;
	buffer.buffer = malloc(buffer.length);
	if (!buffer.buffer) { mylog("Out of memory"); exit(500); }

	time_t st = time(NULL);
	for (i = start;; i++) {
		if (i >= NUM_DNS) { i = 0; }
		if (b) {
			if (i == start) { break; }
			if (time(NULL) - st >= 30) { break; }
		} else {
			b = 1;
		}
		// forward the packet to the tcp dns server
		rc = tcp_query(qa->resp.buffer, &buffer, qa->resp.length, dns_servers[i]);
		if (rc) {
			mylog("tcp_query DNS %s failed: %d %s", dns_servers[i], rc, rc < 0 ? "Connection reset" : strerror(rc));
			if (rc == ECONNREFUSED) { break; }
		} else {
			m_cur_dns = i;
			// send the reply back to the client (minus the length at the beginning)
			rc = sendto(qa->sock, buffer.buffer + 2, buffer.length - 2, 0, (struct sockaddr *)&qa->client, sizeof(qa->client));
			if (rc < 0) {
				rc = errno;
				mylog("send DNS reply to client failed: %d %s", rc, strerror(rc));
			}
			break;
		}
	}

	free(buffer.buffer);
	free(qa->resp.buffer);
	free(qa);
	return NULL;
}

void udp_listener() {
  int sock, rc, len;
  response buffer;
  struct sockaddr_in dns_listener, dns_client;
  queryargs *qa;

  buffer.length = 2048;
  buffer.buffer = malloc(buffer.length);
  if (!buffer.buffer) { error("[!] Out of memory"); }

  memset(&dns_listener, 0, sizeof(dns_listener));
  dns_listener.sin_family = AF_INET;
  dns_listener.sin_port = htons(LISTEN_PORT);
  dns_listener.sin_addr.s_addr = inet_addr(LISTEN_ADDR);

  // create our udp listener
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    error("[!] Error setting up dns proxy");

  if(bind(sock, (struct sockaddr*)&dns_listener, sizeof(dns_listener)) < 0)
    error("[!] Error binding on dns proxy");

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
      error("[!] Error opening logfile.");
  }

  if (!getuid()) {
    if (setgid(getgrnam(GROUPNAME)->gr_gid) < 0) { fprintf(stderr, "setgid failed: %s\n", strerror(errno)); }
    if (setuid(getpwnam(USERNAME)->pw_uid) < 0) { fprintf(stderr, "setuid failed: %s\n", strerror(errno)); }
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

	if(fork() != 0) { exit(0); }
	if(fork() != 0) { exit(0); }
  } else {
	printf("[*] Run in foreground.\n");
  }

  socklen_t dns_client_size;

  pthread_t pthid;
  pthread_attr_t thattr;
  pthread_attr_init(&thattr);
  pthread_attr_setstacksize(&thattr, 32768);

  for (;;) {
    dns_client_size = sizeof(struct sockaddr_in);
    // receive a dns request from the client
    len = recvfrom(sock, buffer.buffer, buffer.length, 0, (struct sockaddr *)&dns_client, &dns_client_size);

    // other invalid values from recvfrom
    if (len < 0) {
      if (errno != EINTR) { mylog("recvfrom failed: %s", strerror(errno)); }
      continue;
    } else if (!len || len >= buffer.length) {
      continue;
    }

    qa = calloc(1, sizeof(*qa));
    if (!qa) { mylog("Out of memory"); exit(500); }
    qa->resp.length = len + 2;
    qa->resp.buffer = malloc(qa->resp.length);
    if (!qa->resp.buffer) { mylog("Out of memory"); exit(500); }
    *((uint16_t *) qa->resp.buffer) = htons(len);
    memcpy(qa->resp.buffer + 2, buffer.buffer, len);
    qa->sock = sock;
    memcpy(&qa->client, &dns_client, sizeof(struct sockaddr_in));

    rc = pthread_create(&pthid, &thattr, query_thread, qa);
    if (rc) {
    	mylog("pthread_create failed: %d %s", rc, strerror(rc));
    	free(qa->resp.buffer);
    	free(qa);
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
    exit(1);
  }
  if (!getgrnam(GROUPNAME)) {
    printf("[!] Group (%s) does not exist! Quiting\n", GROUPNAME);
    exit(1);
  }

  // start the dns proxy
  udp_listener();
  exit(EXIT_SUCCESS);
}
