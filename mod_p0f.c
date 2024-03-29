/*
 * ProFTPD - mod_p0fp
 * Copyright (c) 2011-2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * --- DO NOT EDIT BELOW THIS LINE ---
 */

#include "mod_p0f.h"

extern xaset_t *server_list;

module p0f_module;

int p0f_logfd = -1;
pool *p0f_pool = NULL;

static int p0f_engine = FALSE;
static const char *p0f_logname = NULL;
static pid_t p0f_proc_pid;

static unsigned long p0f_opts = 0UL;
#define P0F_OPT_VERBOSE_LOGGING		0x001

/* Number of seconds to wait for the p0f process to stop before we terminate
 * it with extreme prejudice.
 *
 * Currently this has a granularity of seconds; needs to be in millsecs
 * (e.g. for 500 ms timeout).
 */
static time_t p0f_timeout = 1;

static const char *trace_channel = "p0f";

/* The types of data that p0f provides, and that we care about. */
static const char *p0f_os = NULL;
static const char *p0f_os_details = NULL;
static const char *p0f_network_distance = NULL;
static const char *p0f_network_link = NULL;
static const char *p0f_traffic_type = NULL;

/* Names of supported P0F values */
struct p0f_filter_key {
  const char *filter_name;
  int filter_id;
};

#define P0F_FILTER_KEY_OS		200
#define P0F_FILTER_KEY_OS_DETAILS	201
#define P0F_FILTER_KEY_NETWORK_DISTANCE	202
#define P0F_FILTER_KEY_NETWORK_LINK	203
#define P0F_FILTER_KEY_TRAFFIC_TYPE	204

static struct p0f_filter_key p0f_filter_keys[] = {
  { "OS",		P0F_FILTER_KEY_OS },
  { "OSDetails",	P0F_FILTER_KEY_OS_DETAILS },
  { "NetworkDistance",	P0F_FILTER_KEY_NETWORK_DISTANCE },
  { "NetworkLink",	P0F_FILTER_KEY_NETWORK_LINK },
  { "TrafficType",	P0F_FILTER_KEY_TRAFFIC_TYPE },

  { NULL, -1 }
};

/* The following are from the p0f-query.h header file that comes with the
 * p0f source code.  It is copied (in part) into here directly so that I can
 * avoid a dependency on the p0f source code (and its transitive dependencies,
 * e.g. the other headers and data types used).
 */
#define QUERY_MAGIC	0x0defaced

#define NO_SCORE	-100

/* Masquerade detection flags: */
#define D_GENRE		0x0001
#define D_DETAIL	0x0002
#define D_LINK		0x0004
#define D_DIST		0x0008
#define D_NAT		0x0010
#define D_FW		0x0020
#define D_NAT2_1	0x0040
#define D_FW2_1		0x0080
#define D_NAT2_2	0x0100
#define D_FW2_2		0x0200
#define D_FAST		0x0400
#define D_TNEG		0x0800

#define D_TIME		0x4000
#define D_FAR		0x8000

#define QTYPE_FINGERPRINT	1
#define QTYPE_STATUS		2

struct p0f_query {
  uint32_t magic;		/* must be set to QUERY_MAGIC */
  uint8_t type;			/* QTYPE_* */
  uint32_t id;			/* Unique query ID */
  uint32_t src_ad, dst_ad;	/* src address, local dst addr */
  uint16_t src_port, dst_port;	/* src and dst ports */
};

#define RESP_OK		0	/* Response OK */
#define RESP_BADQUERY	1	/* Query malformed */
#define RESP_NOMATCH	2	/* No match for src-dst data */
#define RESP_STATUS	255	/* Status information */

struct p0f_response {
  uint32_t magic;		/* QUERY_MAGIC */
  uint32_t id;			/* Query ID (copied from p0f_query) */
  uint8_t type;			/* RESP_* */

  uint8_t genre[20];		/* OS genre (empty if no match) */
  uint8_t detail[40];		/* OS version (empty if no match) */
  int8_t dist;			/* Distance (-1 if unknown ) */
  uint8_t link[30];		/* Link type (empty if unknown) */
  uint8_t tos[30];		/* Traffic type (empty if unknown) */
  uint8_t fw,nat;		/* firewall and NAT flags flags */
  uint8_t real;			/* A real operating system? */
  int16_t score;		/* Masquerade score (or NO_SCORE) */
  uint16_t mflags;		/* Masquerade flags (D_*) */
  int32_t uptime;		/* Uptime in hours (-1 = unknown) */
};

/* Convenience struct used to package up all of the info needed to start the
 * p0f executable.
 */
struct p0f_info {
  char *p0f_path;
  char *sigs_path;
  char *device;
  char *log_path;
  char *sock_path;
  char *user;
  unsigned int cache_size;
  char *bpf_rule;
};

#define P0F_READ_MAX_ATTEMPTS	10

static void p0f_set_value(const char *key, const char *value) {
  int res;

  res = pr_env_set(p0f_pool, key, value);
  if (res < 0) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error setting %s environment variable: %s", key, strerror(errno));
  }

  res = pr_table_add_dup(session.notes, pstrdup(session.pool, key),
    (char *) value, 0);
  if (res < 0) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error adding %s session note: %s", key, strerror(errno));
  }

  pr_trace_msg(trace_channel, 3, "set %s = '%s'", key, value);
}

static int p0f_set_info(struct p0f_response *resp) {

  /* resp.genre */
  if (resp->genre[0] != '\0') {
    p0f_os = pstrndup(p0f_pool, (const char *) resp->genre,
      sizeof(resp->genre));
    p0f_set_value("P0F_OS", p0f_os);

  } else {
    pr_trace_msg(trace_channel, 15, "%s", "no p0f genre/OS data available");
  }

  /* resp.detail */
  if (resp->detail[0] != '\0') {
    p0f_os_details = pstrndup(p0f_pool, (const char *) resp->detail,
      sizeof(resp->detail));
    p0f_set_value("P0F_OS_DETAILS", p0f_os_details);

  } else {
    pr_trace_msg(trace_channel, 15, "%s",
      "no p0f detail/OSDetails data available");
  }

  /* resp.distance */
  if (resp->dist != -1) {
    char buf[32];

    memset(buf, '\0', sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "%u", resp->dist);

    p0f_network_distance = pstrdup(p0f_pool, buf);
    p0f_set_value("P0F_NETWORK_DISTANCE", p0f_network_distance);

  } else {
    pr_trace_msg(trace_channel, 15, "%s",
      "no p0f distance/NetworkDistance data available");
  }

  /* resp.link */
  if (resp->link[0] != '\0') {
    p0f_network_link = pstrndup(p0f_pool, (const char *) resp->link,
      sizeof(resp->link));
    p0f_set_value("P0F_NETWORK_LINK", p0f_network_link);

  } else {
    pr_trace_msg(trace_channel, 15, "%s",
      "no p0f link/NetworkLink data available");
  }

  /* resp.tos */
  if (resp->tos[0] != '\0') {
    p0f_traffic_type = pstrndup(p0f_pool, (const char *) resp->tos,
      sizeof(resp->tos));
    p0f_set_value("P0F_TRAFFIC_TYPE", p0f_traffic_type);

  } else {
    pr_trace_msg(trace_channel, 15, "%s",
      "no p0f tos/TrafficType data available");
  }

  /* XXX Not currently reported:
   *
   *  resp.score
   *  resp.fw
   *  resp.nat
   *  resp.real
   *  resp.uptime
   */

  return 0;
}

static int p0f_get_info(const char *p0f_socket) {
  unsigned int nattempts = 0;
  int ok = FALSE, res, sockfd;
  struct in_addr *addr;
  struct sockaddr_un sock;
  struct p0f_query req;
  struct p0f_response resp;

  /* Open a Unix domain socket to the P0FSocket */
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error opening Unix domain socket: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  memset(&sock, 0, sizeof(sock));
  sock.sun_family = AF_UNIX;

  /* Make sure we copy the trailing NUL, too. */
  sstrncpy(sock.sun_path, p0f_socket, sizeof(sock.sun_path));

  res = connect(sockfd, (struct sockaddr *) &sock, sizeof(sock));
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error connecting to Unix domain socket '%s': %s", p0f_socket,
      strerror(xerrno));

    (void) close(sockfd);
    errno = xerrno;
    return -1;
  }

  memset(&req, 0, sizeof(req));

  req.magic = QUERY_MAGIC;
  req.id = session.pid;
  req.type = QTYPE_FINGERPRINT;

  /* XXX This doesn't look like it will for IPv6 addresses.  Not sure whether
   * p0f support queries using IPv6 addresses yet.
   */
  addr = (struct in_addr *) pr_netaddr_get_inaddr(session.c->remote_addr);
  req.src_ad = addr->s_addr;
  req.src_port = session.c->remote_port;

  addr = (struct in_addr *) pr_netaddr_get_inaddr(session.c->local_addr);
  req.dst_ad = addr->s_addr;
  req.dst_port = session.c->local_port;

  pr_trace_msg(trace_channel, 15,
    "p0f query: src addr = %lu (%s), src port = %u, dst addr = %lu, dst port = %u", (unsigned long) req.src_ad, session.c->remote_name, (unsigned int) req.src_port, (unsigned long) req.dst_ad, (unsigned int) req.dst_port);

  res = write(sockfd, &req, sizeof(req));

  /* XXX Do we need to worry about short writes? Probably not; these data are
   * small enough to fit in the PIPE_BUF constant, right?
   */
  if (res != sizeof(req)) {
    int xerrno = errno;

    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error writing to Unix domain socket '%s': %s", p0f_socket,
      strerror(xerrno));

    (void) close(sockfd);
    errno = xerrno;
    return -1;
  }

  while (nattempts < P0F_READ_MAX_ATTEMPTS) {
    pr_signals_handle();

    memset(&resp, 0, sizeof(resp));
    res = read(sockfd, &resp, sizeof(resp));

    if (res != sizeof(resp)) {
      int xerrno = errno;

      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error reading from Unix domain socket '%s': %s", p0f_socket,
        strerror(xerrno));
  
      (void) close(sockfd);
      errno = xerrno;
      return -1;
    }

    nattempts++;

    if (resp.magic != QUERY_MAGIC) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "received bad response (wrong code) from p0f on Unix domain "
        "socket '%s', ignoring", p0f_socket);
      continue;
    }

    /* Check the request/response IDs; it's possible that p0f gave us the
     * wrong response.  Not sure how often that happens, or how long we will
     * want to wait for the correct response.
     */
    if (resp.id != req.id) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "received bad response (mismatched ID) from p0f on Unix domain "
        "socket '%s', ignoring", p0f_socket);
      continue;
    }

    if (resp.type == RESP_BADQUERY) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "received 'bad query' response from p0f on Unix domain socket '%s'",
        p0f_socket);
      break;

    } else if (resp.type == RESP_NOMATCH) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "received 'no match' response from p0f on Unix domain socket '%s'",
        p0f_socket);
      break;
    }

    ok = TRUE;
    break;
  }

  /* Don't need the Unix domain socket open anymore. */
  (void) close(sockfd);

  if (ok) {
    pr_trace_msg(trace_channel, 15, "%s",
      "successfully queried p0f process for info");
    res = p0f_set_info(&resp);

  } else {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "tried %u %s unsuccessfully to query p0f process", nattempts,
      nattempts != 1 ? "times" : "time");
    errno = ENOENT;
    res = -1;
  }

  return res;
}

static char **p0f_get_argv(struct p0f_info *pi, char *name) {
  array_header *argv_list;

  argv_list = make_array(p0f_pool, 5, sizeof(char **));
  *((char **) push_array(argv_list)) = name;

  if (!(p0f_opts & P0F_OPT_VERBOSE_LOGGING)) {
    /* XXX Not sure whether these options should be hardcoded. */
    *((char **) push_array(argv_list)) = "-qKU";
  }

  *((char **) push_array(argv_list)) = "-Q";
  *((char **) push_array(argv_list)) = pi->sock_path;

  if (pi->cache_size > 0) {
    char buf[32];

    memset(buf, '\0', sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "%u", pi->cache_size);

    *((char **) push_array(argv_list)) = "-c";
    *((char **) push_array(argv_list)) = pstrdup(p0f_pool, buf);
  }

  if (pi->sigs_path != NULL) {
    *((char **) push_array(argv_list)) = "-f";
    *((char **) push_array(argv_list)) = pi->sigs_path;
  }

  if (pi->device != NULL) {
    *((char **) push_array(argv_list)) = "-i";
    *((char **) push_array(argv_list)) = pi->device;
  }

  if (pi->log_path != NULL) {
    *((char **) push_array(argv_list)) = "-o";
    *((char **) push_array(argv_list)) = pi->log_path;
  }

  if (pi->user != NULL) {
    *((char **) push_array(argv_list)) = "-u";
    *((char **) push_array(argv_list)) = pi->user;
  }

  if (pi->bpf_rule != NULL) {
    *((char **) push_array(argv_list)) = pi->bpf_rule;
  }

  /* Don't forget the terminating NULL. */
  *((char **) push_array(argv_list)) = NULL;

  return argv_list->elts;
}

static char **p0f_get_env(struct p0f_info *pi) {
  array_header *env_list;

  env_list = make_array(p0f_pool, 1, sizeof(char **));
  *((char **) push_array(env_list)) = NULL;

  return env_list->elts;
}

static void p0f_prepare_fds(void) {
  int fd;
  long nfiles = 0;
  register unsigned int i = 0;
  struct rlimit rlim;

  /* Dup STDIN to /dev/null. */
  fd = open("/dev/null", O_RDONLY);
  if (fd < 0) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error: unable to open /dev/null for stdin: %s", strerror(errno));

  } else {
    if (dup2(fd, STDIN_FILENO) < 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error: unable to dup fd %d to stdin: %s", fd, strerror(errno));
    }

    (void) close(fd);
  }

  if (p0f_logfd >= 0) {
    /* Dup STDOUT to p0f_logfd. */
    if (dup2(p0f_logfd, STDOUT_FILENO) < 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error: unable to dup fd %d to stdout: %s", p0f_logfd, strerror(errno));
    }

  } else {
    /* Dup STDOUT to /dev/null. */
    fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error: unable to open /dev/null for stdout: %s", strerror(errno));

    } else {
      if (dup2(fd, STDOUT_FILENO) < 0) {
        (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
          "error: unable to dup fd %d to stdout: %s", fd, strerror(errno));
      }

      (void) close(fd);
    }
  }

  if (p0f_logfd >= 0) {
    /* Dup STDERR to p0f_logfd. */
    if (dup2(p0f_logfd, STDERR_FILENO) < 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error: unable to dup fd %d to stderr: %s", p0f_logfd, strerror(errno));
    }

  } else {
    /* Dup STDERR to /dev/null. */
    fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "error: unable to open /dev/null for stderr: %s", strerror(errno));

    } else {
      if (dup2(fd, STDERR_FILENO) < 0) {
        (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
          "error: unable to dup fd %d to stderr: %s", fd, strerror(errno));
      }

      (void) close(fd);
    }
  }

  /* Make sure not to pass on open file descriptors.  For stdin/stdout/stderr,
   * we dup /dev/null.
   *
   * First, use getrlimit() to obtain the maximum number of open files
   * for this process -- then close that number.
   */
#if defined(RLIMIT_NOFILE) || defined(RLIMIT_OFILE)
# if defined(RLIMIT_NOFILE)
  if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
# elif defined(RLIMIT_OFILE)
  if (getrlimit(RLIMIT_OFILE, &rlim) < 0) {
# endif
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "getrlimit() error: %s", strerror(errno));

    /* Pick some arbitrary high number. */
    nfiles = 1024;

  } else {
    nfiles = rlim.rlim_max;
  }

#else /* no RLIMIT_NOFILE or RLIMIT_OFILE */
   nfiles = 1024;
#endif

  /* Yes, using a long for the nfiles variable is not quite kosher; it should
   * be an unsigned type, otherwise a large limit (say, RLIMIT_INFINITY)
   * might overflow the data type.  In that case, though, we want to know
   * about it -- and using a signed type, we will know if the overflowed
   * value is a negative number.  Chances are we do NOT want to be closing
   * fds whose value is as high as they can possibly get; that's too many
   * fds to iterate over.  Long story short, using a long int is just fine.
   */

  if (nfiles < 0) {
    nfiles = 1024;
  }

  /* Close the "non-standard" file descriptors. */
  for (i = 3; i < nfiles; i++) {

    /* This is a potentially long-running loop, so handle signals. */
    pr_signals_handle();

    (void) close(i);
  }

  return;
}

static int p0f_exec(struct p0f_info *pi) {
  register unsigned int i;
  char **argv = NULL, **env = NULL, *path, *ptr;

  /* Trim the given path to the command to execute to just the last
   * component; this name will be the first argument to the executed
   * command, as per execve(2) convention.
   */
  path = pi->p0f_path;
  ptr = strrchr(path, '/');
  if (ptr != NULL) {
    path = ptr + 1;
  }

  argv = p0f_get_argv(pi, path);

  (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
    "preparing to execute '%s':", pi->p0f_path);
  for (i = 1; argv[i] != NULL; i++) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION, " argv[%u]: %s", i,
      argv[i]);
  }

  env = p0f_get_env(pi);
  p0f_prepare_fds();

  /* Switch to a permissive umask, so that the query socket that p0f
   * creates will be usable by the session processes.
   */
  umask(000);

  errno = 0;

  if (execve(pi->p0f_path, argv, env) < 0) {
    if (p0f_logfd >= 0) {
      /* We can do this, because stderr has been redirected to P0FLog. */
      fprintf(stderr, "%s: error executing '%s': %s\n", MOD_P0F_VERSION,
        pi->p0f_path, strerror(errno));
    }
  }

  /* Since all previous file descriptors (including those for log files)
   * have been closed, and root privs have been revoked, there's little
   * chance of directing a message of execve() failure to proftpd's log
   * files.  execve() only returns if there's an error; the only way we
   * can signal this to the waiting parent process is to exit with a
   * non-zero value (the value of errno will do nicely).
   */
  exit(errno);
}

static pid_t p0f_start(struct p0f_info *pi) {
  pid_t p0f_pid;

  p0f_pid = fork();
  switch (p0f_pid) {
    case -1:
      pr_log_pri(PR_LOG_ERR, MOD_P0F_VERSION ": unable to fork: %s",
        strerror(errno));
      return 0;

    case 0:
      /* We're the child. */
      break;

    default:
      /* We're the parent. */
      return p0f_pid;
  }

  /* Reset the cached PID, so that it is correctly reflected in the logs. */
  session.pid = getpid();

  /* Install our own signal handlers (mostly to ignore signals) */
  (void) signal(SIGALRM, SIG_IGN);
  (void) signal(SIGHUP, SIG_IGN);
  (void) signal(SIGUSR1, SIG_IGN);
  (void) signal(SIGUSR2, SIG_IGN);

  /* Remove our event listeners. */
  pr_event_unregister(&p0f_module, NULL, NULL);

  PRIVS_ROOT

  if (p0f_exec(pi) < 0) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error executing p0f: %s", strerror(errno));
  }

  /* When we are done, we simply exit. */;
  exit(0);
}

static void p0f_stop(pid_t p0f_pid) {
  int res, status;
  time_t start_time = time(NULL);

  if (p0f_pid == 0) {
    /* Nothing to do. */
    return;
  }

  /* Litmus test: is the p0f process still around?  If not, there's
   * nothing for us to do.
   */
  res = kill(p0f_pid, 0);
  if (res < 0 &&
      errno == ESRCH) {
    return;
  }
  
  res = kill(p0f_pid, SIGTERM);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error sending SIGTERM (signal %d) to p0f process ID %lu: %s",
      SIGTERM, (unsigned long) p0f_pid, strerror(xerrno));
  }

  /* Poll every 500 millsecs. */
  pr_timer_usleep(500 * 1000);

  res = waitpid(p0f_pid, &status, WNOHANG);
  while (res <= 0) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      if (errno == ECHILD) {
        /* XXX Maybe we shouldn't be using waitpid(2) here, since the
         * main SIGCHLD handler may handle the termination of the SNMP
         * agent process?
         */

        return;
      }

      if (errno != EINTR) {
        (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
          "error waiting for p0f process ID %lu: %s",
          (unsigned long) p0f_pid, strerror(errno));
        status = -1;
        break;
      }
    }

    /* Check the time elapsed since we started. */
    if ((time(NULL) - start_time) > p0f_timeout) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "p0f process ID %lu took longer than timeout (%lu secs) to "
        "stop, sending SIGKILL (signal %d)", (unsigned long) p0f_pid,
        p0f_timeout, SIGKILL);
      res = kill(p0f_pid, SIGKILL);
      if (res < 0) {
        (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
         "error sending SIGKILL (signal %d) to SNMP agent process ID %lu: %s",
         SIGKILL, (unsigned long) p0f_pid, strerror(errno));
      }

      break;
    }

    /* Poll every 500 millsecs. */
    pr_timer_usleep(500 * 1000);
  }

  if (WIFEXITED(status)) {
    int exit_status;

    exit_status = WEXITSTATUS(status);
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "p0f process ID %lu terminated normally, with exit status %d",
      (unsigned long) p0f_pid, exit_status);
  }

  if (WIFSIGNALED(status)) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "p0f process ID %lu died from signal %d",
      (unsigned long) p0f_pid, WTERMSIG(status));

    if (WCOREDUMP(status)) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "p0f process ID %lu created a coredump",
        (unsigned long) p0f_pid);
    }
  }

  return;
}

static const char *p0f_get_filter_name(int filter_id) {
  register unsigned int i;

  for (i = 0; p0f_filter_keys[i].filter_name != NULL; i++) {
    if (p0f_filter_keys[i].filter_id == filter_id) {
      return p0f_filter_keys[i].filter_name;
    }
  }

  errno = ENOENT;
  return NULL;
}

static const char *p0f_get_filter_value(int filter_id) {
  switch (filter_id) {
    case P0F_FILTER_KEY_OS:
      if (p0f_os != NULL) {
        return p0f_os;
      }
      break;

    case P0F_FILTER_KEY_OS_DETAILS:
      if (p0f_os_details != NULL) {
        return p0f_os_details;
      }
      break;

    case P0F_FILTER_KEY_NETWORK_DISTANCE:
      if (p0f_network_distance != NULL) {
        return p0f_network_distance;
      }
      break;

    case P0F_FILTER_KEY_NETWORK_LINK:
      if (p0f_network_link != NULL) {
        return p0f_network_link;
      }
      break;

    case P0F_FILTER_KEY_TRAFFIC_TYPE:
      if (p0f_traffic_type != NULL) {
        return p0f_traffic_type;
      }
      break;
  }

  errno = ENOENT;
  return NULL;
}

static int p0f_check_filters(cmd_rec *cmd, char *path) {
#if PR_USE_REGEX
  config_rec *c;

  c = find_config(get_dir_ctxt(cmd->tmp_pool, path), CONF_PARAM,
    "P0FAllowFilter", FALSE);
  while (c) {
    int filter_id, matched_cmd = FALSE, res;
    pr_regex_t *filter_re;
    char **cmdlist, *xfer_cmd;
    const char *filter_name, *filter_pattern, *filter_value;

    pr_signals_handle();

    cmdlist = (char **) c->argv[0];

    /* First, check the command list. */
    for (xfer_cmd = *cmdlist; xfer_cmd; xfer_cmd = *(cmdlist++)) {
      if (strcasecmp(xfer_cmd, cmd->argv[0]) == 0) {
        matched_cmd = TRUE;
        break;
      }
    }

    if (matched_cmd == FALSE) {
      c = find_config_next(c, c->next, CONF_PARAM, "P0FAllowFilter", FALSE);
      continue;
    }

    filter_id = *((int *) c->argv[1]);
    filter_pattern = c->argv[2];
    filter_re = c->argv[3];

    filter_value = p0f_get_filter_value(filter_id);
    if (filter_value == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "P0FAllowFilter", FALSE);
      continue;
    }

    filter_name = p0f_get_filter_name(filter_id);

    res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
    pr_trace_msg(trace_channel, 12,
      "%s filter value %s %s P0FAllowFilter pattern '%s'",
      filter_name, filter_value, res == 0 ? "matched" : "did not match",
      filter_pattern);

    if (res != 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "%s filter value '%s' did not match P0FAllowFilter pattern '%s'",
        filter_name, filter_value, filter_pattern);
      return -1;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "P0FAllowFilter", FALSE);
  }

  c = find_config(get_dir_ctxt(cmd->tmp_pool, path), CONF_PARAM,
    "P0FDenyFilter", FALSE);
  while (c) {
    int filter_id, matched_cmd = FALSE, res;
    pr_regex_t *filter_re;
    char **cmdlist, *xfer_cmd;
    const char *filter_name, *filter_pattern, *filter_value;

    pr_signals_handle();

    /* First, check the command list. */
    cmdlist = (char **) c->argv[0];

    for (xfer_cmd = *cmdlist; xfer_cmd; xfer_cmd = *(cmdlist++)) {
      if (strcasecmp(xfer_cmd, cmd->argv[0]) == 0) {
        matched_cmd = TRUE;
        break;
      }
    }

    if (matched_cmd == FALSE) {
      c = find_config_next(c, c->next, CONF_PARAM, "P0FDenyFilter", FALSE);
      continue;
    }

    filter_id = *((int *) c->argv[1]);
    filter_pattern = c->argv[2];
    filter_re = c->argv[3];

    filter_value = p0f_get_filter_value(filter_id);
    if (filter_value == NULL) {
      c = find_config_next(c, c->next, CONF_PARAM, "P0FDenyFilter", FALSE);
      continue;
    }

    filter_name = p0f_get_filter_name(filter_id);

    res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
    pr_trace_msg(trace_channel, 12,
      "%s filter value %s %s P0FAllowFilter pattern '%s'",
      filter_name, filter_value, res == 0 ? "matched" : "did not match",
      filter_pattern);

    if (res == 0) {
      (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
        "%s filter value '%s' matched P0FDenyFilter pattern '%s'",
        filter_name, filter_value, filter_pattern);
      return -1;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "P0FDenyFilter", FALSE);
  }
#endif /* !HAVE_REGEX_H or !HAVE_REGCOMP */

  return 0;
}

static char *p0f_get_path_skip_opts(cmd_rec *cmd) {
  char *ptr, *path = NULL;

  if (cmd->arg == NULL) {
    errno = ENOENT;
    return NULL;
  }

  ptr = path = cmd->arg;

  while (isspace((int) *ptr)) {
    pr_signals_handle();
    ptr++;
  }

  if (*ptr == '-') {
    /* Options are found; skip past the leading whitespace. */
    path = ptr;
  }

  while (path &&
         *path == '-') {

    /* Advance to the next whitespace */
    while (*path != '\0' &&
           !isspace((int) *path)) {
      path++;
    }

    ptr = path;

    while (*ptr &&
           isspace((int) *ptr)) {
      pr_signals_handle();
      ptr++;
    }

    if (*ptr == '-') {
      /* Options are found; skip past the leading whitespace. */
      path = ptr;

    } else if (*(path + 1) == ' ') {
      /* If the next character is a blank space, advance just one character. */
      path++;
      break;

    } else {
      path = ptr;
      break;
    }
  }

  return path;
}

static char *p0f_get_path(cmd_rec *cmd, const char *proto) {
  char *path = NULL, *abs_path = NULL;

  if (strncasecmp(proto, "ftp", 4) == 0 ||
      strncasecmp(proto, "ftps", 5) == 0) {

    if (pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
        pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0) {
      path = p0f_get_path_skip_opts(cmd);


    } else {
      path = cmd->arg;
    }

  } else if (strncasecmp(proto, "sftp", 5) == 0) {
    path = cmd->arg;

  } else {
    pr_trace_msg(trace_channel, 1,
      "unable to get path from command: unsupported protocol '%s'", proto);
    errno = EINVAL;
    return NULL;
  }

  abs_path = dir_abs_path(cmd->tmp_pool, path, TRUE);
  if (abs_path == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1, "error resolving '%s': %s", path,
      strerror(xerrno));

    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 17, "resolved path '%s' to '%s'", path, abs_path);
  return abs_path;
}

static void p0f_set_error_response(cmd_rec *cmd, const char *msg) {
  if (pr_cmd_cmp(cmd, PR_CMD_LIST_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_NLST_ID) == 0) {
    size_t arglen;

    /* We have may received bare LIST/NLST commands, or just options and no
     * paths.  Do The Right Thing(tm) with these scenarios.
     */

    arglen = strlen(cmd->arg);
    if (arglen == 0) {
      /* No options, no path. */
      pr_response_add_err(R_450, ".: %s", msg);

    } else {
      char *path;

      path = p0f_get_path_skip_opts(cmd);

      arglen = strlen(path);
      if (arglen == 0) {
        /* Only options, no path. */
        pr_response_add_err(R_450, ".: %s", msg);

      } else {
        pr_response_add_err(R_450, "%s: %s", cmd->arg, msg);
      }
    }

  } else if (pr_cmd_cmp(cmd, PR_CMD_MLSD_ID) == 0 ||
             pr_cmd_cmp(cmd, PR_CMD_MLST_ID) == 0) {
    size_t arglen;

    arglen = strlen(cmd->arg);
    if (arglen == 0) {

      /* No path. */
      pr_response_add_err(R_550, ".: %s", msg);

    } else {
      pr_response_add_err(R_550, "%s: %s", cmd->arg, msg);
    }

  } else if (pr_cmd_cmp(cmd, PR_CMD_STAT_ID) == 0) {
    size_t arglen;

    arglen = strlen(cmd->arg);
    if (arglen == 0) {

      /* No path. */
      pr_response_add_err(R_550, "%s", msg);

    } else {
      pr_response_add_err(R_550, "%s: %s", cmd->arg, msg);
    }

  } else {
    pr_response_add_err(R_550, "%s: %s", cmd->arg, msg);
  }
}

static char *p0f_get_cmd_from_list(char **list) {
  char *res = NULL, *dst = NULL;
  unsigned char quote_mode = FALSE;

  while (**list && isspace((int) **list)) {
    pr_signals_handle();
    (*list)++;
  }

  if (!**list)
    return NULL;

  res = dst = *list;

  if (**list == '\"') {
    quote_mode = TRUE;
    (*list)++;
  }

  while (**list && **list != ',' &&
      (quote_mode ? (**list != '\"') : (!isspace((int) **list)))) {

    pr_signals_handle();

    if (**list == '\\' && quote_mode) {

      /* escaped char */
      if (*((*list) + 1))
        *dst = *(++(*list));
    }

    *dst++ = **list;
    ++(*list);
  }

  if (**list)
    (*list)++;

  *dst = '\0';

  return res;
}

static int p0f_parse_cmdlist(const char *name, config_rec *c, char *cmdlist) {
  char *cmd = NULL;
  array_header *cmds = NULL;

  /* Allocate an array_header. */
  cmds = make_array(c->pool, 0, sizeof(char *));

  /* Add each command to the array, checking for invalid commands or
   * duplicates.
   */
  while ((cmd = p0f_get_cmd_from_list(&cmdlist)) != NULL) {
    pr_signals_handle();

    /* Is the given command a valid one for this directive? */
    if (strcasecmp(cmd, C_APPE) != 0 &&
        strcasecmp(cmd, C_RETR) != 0 &&
        strcasecmp(cmd, C_STOR) != 0 &&
        strcasecmp(cmd, C_STOU) != 0) {
      pr_log_debug(DEBUG0, "invalid %s command: %s", name, cmd);
      errno = EINVAL;
      return -1;
    }

    *((char **) push_array(cmds)) = pstrdup(c->pool, cmd);
  }

  /* Terminate the array with a NULL. */
  *((char **) push_array(cmds)) = NULL;

  /* Store the array of commands in the config_rec. */
  c->argv[0] = (void *) cmds->elts;

  return 0;
}

/* Configuration handlers
 */

/* usage: P0FAllowFilter cmds key regex
 *        P0FDenyFilter cmds key regex
 */
MODRET set_p0ffilter(cmd_rec *cmd) {
#if PR_USE_REGEX
  register unsigned int i;
  config_rec *c;
  pr_regex_t *pre;
  int filter_id = -1, res;

  CHECK_ARGS(cmd, 3);
  CHECK_CONF(cmd, CONF_DIR|CONF_DYNDIR);

  c = add_config_param(cmd->argv[0], 4, NULL, NULL, NULL, NULL);

  if (p0f_parse_cmdlist(cmd->argv[0], c, cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "error with command list");
  }

  /* Make sure a supported filter key was configured. */
  for (i = 0; p0f_filter_keys[i].filter_name != NULL; i++) {
    if (strcasecmp(cmd->argv[2], p0f_filter_keys[i].filter_name) == 0) {
      filter_id = p0f_filter_keys[i].filter_id;
      break;
    }
  }

  if (filter_id == -1) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown ", cmd->argv[0],
      " filter name '", cmd->argv[2], "'", NULL));
  }

  pre = pr_regexp_alloc(&p0f_module);

  res = pr_regexp_compile(pre, cmd->argv[3], REG_EXTENDED|REG_NOSUB|REG_ICASE);
  if (res != 0) {
    char errstr[256];

    memset(errstr, '\0', sizeof(errstr));
    pr_regexp_error(res, pre, errstr, sizeof(errstr)-1);
    pr_regexp_free(&p0f_module, pre);

    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "pattern '", cmd->argv[3],
      "' failed regex compilation: ", errstr, NULL));
  }

  c->argv[1] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[1]) = filter_id;
  c->argv[2] = pstrdup(c->pool, cmd->argv[2]);
  c->argv[3] = pre;
  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0],
    " directive cannot be used on this system, as you do not have POSIX "
    "compliant regex support", NULL));
#endif
}

/* usage: P0FCacheSize size */
MODRET set_p0fcachesize(cmd_rec *cmd) {
  int cache_size;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  cache_size = atoi(cmd->argv[1]);
  if (cache_size <= 0) {
    CONF_ERROR(cmd, "cache size must be greater than zero");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned int));
  *((unsigned int *) c->argv[0]) = cache_size;

  return PR_HANDLED(cmd); 
}

/* usage: P0FDevice device */
MODRET set_p0fdevice(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: P0FEngine on|off */
MODRET set_p0fengine(cmd_rec *cmd) {
  int bool = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: P0FLog path|"none" */
MODRET set_p0flog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: P0FPath /path/to/p0f */
MODRET set_p0fpath(cmd_rec *cmd) {
  const char *path;
  struct stat st;
  int res;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];

  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '", path, "'",
      NULL));
  }

  res = stat(path, &st);
  if (res < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to verify P0FPath '", path,
      "': ", strerror(errno), NULL));
  }

  if (!S_ISREG(st.st_mode)) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use P0FPath '", path,
      "': Not a regular file", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* usage: P0FOptions opt1 ... optN */
MODRET set_p0foptions(cmd_rec *cmd) {
  register unsigned int i;
  unsigned long opts = 0UL;
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "VerboseLogging") == 0) {
      opts |= P0F_OPT_VERBOSE_LOGGING;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown P0FOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: P0FSignatures /path/to/p0f.fp */
MODRET set_p0fsignatures(cmd_rec *cmd) {
  const char *path;
  int res;
  struct stat st;
 
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '", path,
      "'", NULL));
  }

  res = stat(path, &st);
  if (res < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to verify P0FSignatures '",
      path, "': ", strerror(errno), NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* usage: P0FSocket path */
MODRET set_p0fsocket(cmd_rec *cmd) {
  const char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '", path,
      "'", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* usage: P0FUser system-user */
MODRET set_p0fuser(cmd_rec *cmd) {
  const char *name;
  struct passwd *pw;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  name = cmd->argv[1];

  /* Make sure the configured user name is a valid system user. */
  pw = getpwnam(name);
  if (pw == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a valid system user: ",
      name, NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, name);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET p0f_pre_cmd(cmd_rec *cmd) {
  const char *proto;
  char *abs_path;
  int res;

  if (p0f_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  abs_path = p0f_get_path(cmd, proto);

  res = p0f_check_filters(cmd, abs_path);
  if (res < 0) {
    p0f_set_error_response(cmd, strerror(EACCES));
    return PR_ERROR(cmd);
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void p0f_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp((const char *) event_data, "mod_p0f.c") == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&p0f_module, NULL, NULL);

    /* Stop p0f process */
    p0f_stop(p0f_proc_pid);

    destroy_pool(p0f_pool);
    p0f_pool = NULL;

    (void) close(p0f_logfd);
    p0f_logfd = -1;
  }
}
#endif

static void p0f_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "P0FEngine", FALSE);
  if (c != NULL) {
    p0f_engine = *((int *) c->argv[0]);
  }

  if (p0f_engine == FALSE) {
    return;
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FLog", FALSE);
  if (c != NULL) {
    p0f_logname = c->argv[0];

    if (strcasecmp(p0f_logname, "none") != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(p0f_logname, &p0f_logfd, 0600);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_P0F_VERSION
            ": notice: unable to open P0FLog '%s': %s", p0f_logname,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_NOTICE, MOD_P0F_VERSION
            ": notice: unable to open P0FLog '%s': parent directory is "
            "world-writable", p0f_logname);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_NOTICE, MOD_P0F_VERSION
            ": notice: unable to open P0FLog '%s': cannot log to a symlink",
            p0f_logname);
        }
      }
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FSocket", FALSE);
  if (c == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_P0F_VERSION
      ": notice: missing required P0FSocket directive, disabling module");
    p0f_engine = FALSE;
    return;
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FOptions", FALSE);
  if (c != NULL) {
    p0f_opts = *((unsigned long *) c->argv[0]);
  }
}

static void p0f_restart_ev(const void *event_data, void *user_data) {
  if (p0f_engine == FALSE) {
    return;
  }

  /* XXX Stop/start p0f process?  That would ruin its cache, but WOULD pick
   * up any config changes.
   */
}

static void p0f_shutdown_ev(const void *event_data, void *user_data) {
  p0f_stop(p0f_proc_pid);

  destroy_pool(p0f_pool);
  p0f_pool = NULL;

  if (p0f_logfd >= 0) {
    (void) close(p0f_logfd);
    p0f_logfd = -1;
  }
}

static void p0f_startup_ev(const void *event_data, void *user_data) {
  struct p0f_info pi;
  config_rec *c;
  server_rec *s;
  char *bpf_rule = "";

  if (p0f_engine == FALSE) {
    return;
  }

  if (ServerType == SERVER_INETD) {
    p0f_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_P0F_VERSION
      ": cannot support p0f for ServerType inetd, disabling module");
    return;
  }

  memset(&pi, 0, sizeof(pi));

  /* Get all of the p0f info for running the process. */
  pi.p0f_path = "p0f";

  c = find_config(main_server->conf, CONF_PARAM, "P0FPath", FALSE);
  if (c != NULL) {
    pi.p0f_path = c->argv[0];
  }

  if (p0f_logfd >= 0) {
    pi.log_path = (char *) p0f_logname;
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FSocket", FALSE);
  if (c == NULL) {
    pr_log_debug(DEBUG0, MOD_P0F_VERSION
      ": missing required P0FSocket directive, disabling module");
    p0f_engine = FALSE;
    return;
  }
  pi.sock_path = c->argv[0];

  c = find_config(main_server->conf, CONF_PARAM, "P0FSignatures", FALSE);
  if (c != NULL) {
    pi.sigs_path = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FDevice", FALSE);
  if (c != NULL) {
    pi.device = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FUser", FALSE);
  if (c != NULL) {
    pi.user = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FCacheSize", FALSE);
  if (c != NULL) {
    pi.cache_size = *((unsigned int *) c->argv[0]);
  }

  /* Iterate through the server_list, and build up the BPF filter expression,
   * based on the ports on which proftpd is listening.
   */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    char buf[32];

    memset(buf, '\0', sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "%u", s->ServerPort);

    bpf_rule = pstrcat(p0f_pool, bpf_rule,
      *bpf_rule ? "or dst port " : "dst port ", buf, NULL);
  }

  pi.bpf_rule = bpf_rule;

  p0f_proc_pid = p0f_start(&pi);
  if (p0f_proc_pid == 0) {
    p0f_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_P0F_VERSION
      ": failed to start p0f process, disabling module");
  }

  return;
}

/* Initialization routines
 */

static int p0f_init(void) {
  p0f_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(p0f_pool, MOD_P0F_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&p0f_module, "core.module-unload", p0f_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&p0f_module, "core.postparse", p0f_postparse_ev, NULL);
  pr_event_register(&p0f_module, "core.restart", p0f_restart_ev, NULL);
  pr_event_register(&p0f_module, "core.shutdown", p0f_shutdown_ev, NULL);
  pr_event_register(&p0f_module, "core.startup", p0f_startup_ev, NULL);

  return 0;
}

static int p0f_sess_init(void) {
  config_rec *c;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "P0FEngine", FALSE);
  if (c != NULL) {
    p0f_engine = *((int *) c->argv[0]);
  }

  if (p0f_engine == FALSE) {
    return 0;
  }

  /* XXX p0f's query socket API does not support IPv6 connections currently */
  if (pr_netaddr_get_family(session.c->remote_addr) != AF_INET) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION, "%s",
      "unable to support IPv6 connections");
    p0f_engine = FALSE;
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FSocket", FALSE);
  if (c == NULL) {
    /* XXX This shouldn't happen; the lack of a P0FSocket directive should
     * have been caught earlier.
     */
    p0f_engine = FALSE;
    return 0;
  }

  /* Call to p0f process, fill in notes/env vars, check ACL patterns */
  res = p0f_get_info(c->argv[0]);
  if (res < 0) {
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
      "error getting p0f info for connected client: %s", strerror(errno));
  }

  return 0;
}

/* Module API tables
 */

static conftable p0f_conftab[] = {
  { "P0FAllowFilter",	set_p0ffilter,		NULL },
  { "P0FDenyFilter",	set_p0ffilter,		NULL },
  { "P0FCacheSize",	set_p0fcachesize,	NULL },
  { "P0FDevice",	set_p0fdevice,		NULL },
  { "P0FEngine",	set_p0fengine,		NULL },
  { "P0FLog",		set_p0flog,		NULL },
  { "P0FPath",		set_p0fpath,		NULL },
  { "P0FOptions",	set_p0foptions,		NULL },
  { "P0FSignatures",	set_p0fsignatures,	NULL },
  { "P0FSocket",	set_p0fsocket,		NULL },
  { "P0FUser",		set_p0fuser,		NULL },
  { NULL }
};

static cmdtable p0f_cmdtab[] = {
  { PRE_CMD,		C_APPE,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_DELE,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_LIST,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_MLSD,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_MLST,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_NLST,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_RETR,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_RNFR,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_RNTO,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_STAT,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_SIZE,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },
  { PRE_CMD,		C_STOR,	G_NONE,	p0f_pre_cmd,	FALSE,	FALSE },

  { 0, NULL }
};

module p0f_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "p0f",

  /* Module configuration handler table */
  p0f_conftab,

  /* Module command handler table */
  p0f_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  p0f_init,

  /* Session initialization */
  p0f_sess_init,

  /* Module version */
  MOD_P0F_VERSION
};
