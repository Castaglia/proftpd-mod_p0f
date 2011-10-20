/*
 * ProFTPD - mod_p0fp
 * Copyright (c) 2011 TJ Saunders
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
 * DO NOT EDIT BELOW THIS LINE
 * $Archive: mod_p0f.a $
 */

#include "mod_p0f.h"

extern xaset_t *server_list;

module p0f_module;

int p0f_logfd = -1;
pool *p0f_pool = NULL;

static int p0f_engine = FALSE;
static const char *p0f_logname = NULL;
static pid_t p0f_proc_pid;

static const char *trace_channel = "p0f";

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
  const char *p0f_path;
  const char *sigs_path;
  const char *device;
  const char *log_path;
  const char *sock_path;
  const char *user;
  unsigned int cache_size;
  const char *bpf_rule;
};

static int p0f_exec(struct p0f_info *pi) {
  errno = ENOSYS;
  return -1;
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
    (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION
      ": error executing p0f: %s", strerror(errno));
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
        "stop, sending SIGKILL (signal %d)", (unsigned long) agent_pid,
        p0f_timeout, SIGKILL);
      res = kill(p0f_pid, SIGKILL);
      if (res < 0) {
        (void) pr_log_writefile(p0f_logfd, MOD_P0F_VERSION,
         "error sending SIGKILL (signal %d) to SNMP agent process ID %lu: %s",
         SIGKILL, (unsigned long) agent_pid, strerror(errno));
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

/* Configuration handlers
 */

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
  struct stat st;
  int res;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (*cmd->argv[1] != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '",
      cmd->argv[1], "'", NULL));
  }

  res = stat(cmd->argv[1], &st);
  if (res < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to verify P0FPath '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  if (!S_ISREG(st.st_mode)) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use P0FPath '",
      cmd->argv[1], "': Not a regular file", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: P0FSignatures /path/to/p0f.fp */
MODRET set_p0fsignatures(cmd_rec *cmd) {
  int res;
  struct stat st;
 
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);
 
  if (*cmd->argv[1] != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '",
      cmd->argv[1], "'", NULL));
  }

  res = stat(cmd->argv[1], &st);
  if (res < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to verify P0FSignatures '",
      cmd->argv[1], "': ", strerror(errno), NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: P0FSocket path */
MODRET set_p0fsocket(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (*cmd->argv[1] != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '",
      cmd->argv[1], "'", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: P0FUser system-user */
MODRET set_p0fuser(cmd_rec *cmd) {
  struct passwd *pw;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  /* Make sure the configured user name is a valid system user. */
  pw = getpwnam(cmd->argv[1]);
  if (pw == NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a valid system user: ",
      cmd->argv[1], NULL);
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET snmp_pre_list(cmd_rec *cmd) {

  if (p0f_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check abs path against signature whitelist/pattern, if any. */

  return PR_DECLINED(cmd);
}

MODRET snmp_pre_retr(cmd_rec *cmd) {

  if (p0f_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check abs path against signature whitelist/pattern, if any. */

  return PR_DECLINED(cmd);
}

MODRET snmp_pre_stor(cmd_rec *cmd) {

  if (p0f_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Check abs path against signature whitelist/pattern, if any. */

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void p0f_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_p0f.c", 11) == 0) {
    register unsigned int i;

    /* Unregister ourselves from all events. */
    pr_event_unregister(&snmp_module, NULL, NULL);

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
  register unsigned int i;
  config_rec *c;
  server_rec *s;
  int res;

  c = find_config(main_server->conf, CONF_PARAM, "P0FEngine", FALSE);
  if (c) {
    p0f_engine = *((int *) c->argv[0]);
  }

  if (p0f_engine == FALSE) {
    return;
  }

  c = find_config(main_server->conf, CONF_PARAM, "P0FLog", FALSE);
  if (c) {
    p0f_logname = c->argv[0];

    if (strncasecmp(p0f_logname, "none", 5) != 0) {
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

  /* Iterate through the server_list, and count up the number of vhosts. */
  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {

    /* XXX Determine the device(s) needed, and ports, to build up the BPF
     * rule.
     */
  }
}

static void p0f_restart_ev(const void *event_data, void *user_data) {

  if (p0f_engine == FALSE) {
    return;
  }

  /* XXX Stop/start p0f process?
}

static void p0f_shutdown_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  p0f_stop(p0f_proc_pid);

  destroy_pool(p0f_pool);
  p0f_pool = NULL;

  if (p0f_logfd >= 0) {
    (void) close(p0f_logfd);
    p0f_logfd = -1;
  }
}

static void p0f_startup_ev(const void *event_data, void *user_data) {
  config_rec *c;
  struct p0f_info pi;

  if (p0f_engine == FALSE) {
    return;
  }

  if (ServerType == SERVER_INETD) {
    p0f_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_P0F_VERSION
      ": cannot support p0f for ServerType inetd, disabling module");
    return;
  }

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
  if (c) {
    p0f_engine = *((int *) c->argv[0]);
  }

  if (p0f_engine == FALSE) {
    return 0;
  }

  /* Call to p0f process, fill in notes/env vars, check ACL patterns */
  res = p0f_query();
  if (res < 0) {
    /* Check for deny/allow policy, if login acl present? */
  }

  return 0;
}

/* Module API tables
 */

static conftable p0f_conftab[] = {
  { "P0FCacheSize,	set_p0fcachesize,	NULL },
  { "P0FDevice",	set_p0fdevice,		NULL },
  { "P0FEngine",	set_p0fengine,		NULL },
  { "P0FLog",		set_p0flog,		NULL },
  { "P0FPath",		set_p0fpath,		NULL },
  { "P0FSignatures",	set_p0fsignatures,	NULL },
  { "P0FSocket",	set_p0fsocket,		NULL },
  { "P0FUser",		set_p0fuser,		NULL },
  { NULL }
};

static cmdtable p0f_cmdtab[] = {
  { PRE_CMD,		C_LIST,	G_NONE,	p0f_pre_list,	FALSE,	FALSE },
  { PRE_CMD,		C_MLSD,	G_NONE,	p0f_pre_list,	FALSE,	FALSE },
  { PRE_CMD,		C_MLST,	G_NONE,	p0f_pre_list,	FALSE,	FALSE },
  { PRE_CMD,		C_NLST,	G_NONE,	p0f_pre_list,	FALSE,	FALSE },

  { PRE_CMD,		C_RETR,	G_NONE,	p0f_pre_retr,	FALSE,	FALSE },
  { PRE_CMD,		C_STOR,	G_NONE,	p0f_pre_stor,	FALSE,	FALSE },

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

