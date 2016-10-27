/*
 * (c) 2010  Lars Ellenberg <lars@linbit.com>
 * RDS adaption of ucast.c, which in turn was: ...
 * ... well, see the first comment there.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* NOTE
 * This is
 *
 *	====================================
 *	==	NOT PRODUCTION CODE,      ==
 *	====================================
 *
 * but proof of concept only. It will break if things break.
 *
 * It is here only in case someone finds time to pick this up and add RDS
 * specific error handling to sendto() and others, figure out when to use
 * RDS_CANCEL_SENT_TO (and how to get the necessary information into the
 * plugin), how to handle necessary retries on congestion and whatever else is
 * necessary to make it actually work.
 *
 * And, how to sensibly configure (and reconfigure, preferably at runtime)
 * the list of peers this thing talks to.
 *
 * The easiest way to configure it will be to just list all the node names,
 * and have them map to ipv6 addresses using /etc/hosts.
 *     rds eth1 node-a node-b node-c node-d node-e
 * anything that resolves to the ip of eth1 on this node will be skipped,
 * so you can have ha.cf identical on all nodes.
 * If this is ever made fit for production, most likely it should read the list
 * of peers from some config file instead, or get it via some additional API
 * plugin hook.
 *
 * For some information about RDS, see
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=blob;f=Documentation/networking/rds.txt
 */

#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#ifndef HAVE_INET_ATON
	extern  int     inet_aton(const char *, struct in_addr *);
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#if defined(SO_BINDTODEVICE)
#include <net/if.h>
#endif

#include <heartbeat.h>
#include <HBcomm.h>

/*
 * Plugin information
 */
#define PIL_PLUGINTYPE          HB_COMM_TYPE
#define PIL_PLUGINTYPE_S        HB_COMM_TYPE_S
#define PIL_PLUGIN              rds
#define PIL_PLUGIN_S            "rds"
#define PIL_PLUGINLICENSE	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL	URL_LGPL
#include <pils/plugin.h>

/*
 * Macros/Defines
 */
#define ISRDSOBJECT(mp) ((mp) && ((mp)->vf == (void*)&rdsOps))
#define RDSASSERT(mp)	g_assert(ISRDSOBJECT(mp))

#define LOG		PluginImports->log
#define MALLOC		PluginImports->alloc
#define STRDUP		PluginImports->mstrdup
#define FREE		PluginImports->mfree

#define	MAXBINDTRIES	1

static int largest_msg_size = 0;

/*
 * Structure Declarations
 */

struct rds_private {
        char* interface;		/* Interface name */
        struct sockaddr_in my_addr;	/* Local address */
        int port;			/* RDS port */
        int socket;			/* Read/Write-socket */
	int n_peers;			/* how many peers? */

	/* Not a list, but a hash table:
	 * "soon" we should be able to send node messages
	 * only to the destination node, not to all nodes,
	 * and then a "node name" -> "in_addr" key value pair
	 * comes in handy.
	 */
	GHashTable *peer_addresses;
};


/*
 * Function Prototypes
 */

PIL_rc PIL_PLUGIN_INIT(PILPlugin *us, const PILPluginImports *imports);

static int rds_parse(const char *line);
static struct hb_media* rds_new(const char *intf);
static int rds_open(struct hb_media *mp);
static int rds_close(struct hb_media *mp);
static void* rds_read(struct hb_media *mp, int* lenp);
static int rds_write(struct hb_media *mp, void *msg, int len);

static int HB_make_sock(struct hb_media *mp);

static struct rds_private* new_ip_interface(const char *ifn);

static int rds_descr(char **buffer);
static int rds_mtype(char **buffer);
static int rds_isping(void);


/*
 * External Data
 */

extern struct hb_media *sysmedia[];
extern int nummedia;

/*
 * Module Public Data
 */

const char hb_media_name[] = "RDS/IP";

static struct hb_media_fns rdsOps = {
	NULL,
	rds_parse,
	rds_open,
	rds_close,
	rds_read,
	rds_write,
	rds_mtype,
	rds_descr,
	rds_isping
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static struct hb_media_imports*	OurImports;
static void*			interfprivate;
static int			localrdsport;


/*
 * Implmentation
 */

PIL_rc PIL_PLUGIN_INIT(PILPlugin *us, const PILPluginImports *imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);

	/*  Register our interface implementation */
	return imports->register_interface(us, PIL_PLUGINTYPE_S,
		PIL_PLUGIN_S, &rdsOps, NULL,
		&OurInterface, (void*)&OurImports, interfprivate);
}

#define GET_NEXT_TOKEN(bp, token) do {           \
        int toklen;                              \
        bp += strspn(bp, WHITESPACE);            \
        toklen = strcspn(bp, WHITESPACE);        \
        strncpy(token, bp, toklen);              \
        bp += toklen;                            \
        token[toklen] = EOS;                     \
} while(0)

static void free_key_value(gpointer kv)
{
	FREE(kv);
}

static int rds_parse(const char *line)
{
	const char *bp = line;
	struct hb_media *mp;
	struct rds_private *ei;
	char dev[MAXLINE];
	char ip[MAXLINE];

	GET_NEXT_TOKEN(bp, dev);
	if (*dev == EOS) {
		PILCallLog(LOG, PIL_CRIT, "rds statement without device");
		return HA_FAIL;
	}
	mp = rds_new(dev);
	if (!mp)
		return HA_FAIL;

	ei = mp->pd;
	PILCallLog(LOG, PIL_DEBUG, "rds: on %s %s:%d",
		ei->interface, inet_ntoa(ei->my_addr.sin_addr), localrdsport);
	ei->peer_addresses = g_hash_table_new_full(g_str_hash, g_str_equal,
			free_key_value, free_key_value);
	if (ei->peer_addresses == NULL) {
		PILCallLog(LOG, PIL_CRIT, "rds: g_hash_table_new_full failed");
		goto fail;
	}
	for (;;) {
		char *name;
		struct sockaddr_in *addr;
		struct hostent *h;

		/* FIXME get node names from somewhere else,
		 * not specify them on the rds media line again */
		GET_NEXT_TOKEN(bp, ip);
		if (*ip == EOS)
			break;
		h = gethostbyname(ip);
		if (!h) {
			PILCallLog(LOG, PIL_CRIT,
				"rds: cannot resolve hostname %s", ip);
			goto fail;
		}

		if (ei->my_addr.sin_addr.s_addr ==
		    ((struct in_addr *)h->h_addr_list[0])->s_addr) {
			PILCallLog(LOG, PIL_DEBUG, "rds: %s skipping my own address",
					ei->interface);
			continue;
		}

		addr = MALLOC(sizeof(*addr));
		if (!addr) {
			PILCallLog(LOG, PIL_CRIT, "rds: cannot alloc addr");
			goto fail;
		}
		name = STRDUP(h->h_name);
		if (!name) {
			PILCallLog(LOG, PIL_CRIT, "rds: cannot strdup name");
			FREE(addr);
			goto fail;
		}

		addr->sin_family = AF_INET;
		addr->sin_port = htons(localrdsport);
		memcpy(&addr->sin_addr, h->h_addr_list[0], sizeof(*addr));
		g_hash_table_insert(ei->peer_addresses, name, addr);
		PILCallLog(LOG, PIL_DEBUG, "rds: %s %s -> %s",
				ei->interface, name, inet_ntoa(addr->sin_addr));
		ei->n_peers++;
	}

	/* we found some, and now reached the end of the list */
	if (ei->n_peers) {
		sysmedia[nummedia++] = mp;
		return HA_OK;
	}

	/* empty list? */
	PILCallLog(LOG, PIL_CRIT, "rds: [%s] missing target IP address/hostname", dev);

fail:
	if (ei->peer_addresses) {
		g_hash_table_destroy(ei->peer_addresses);
		ei->peer_addresses = NULL;
	}

	FREE(ei->interface);
	FREE(mp->pd);
	FREE((void*)(unsigned long)(mp->name));
	FREE(mp);
	return HA_FAIL;
}

static int rds_mtype(char **buffer)
{
	*buffer = STRDUP(PIL_PLUGIN_S);
	if (!*buffer) {
		PILCallLog(LOG, PIL_CRIT, "rds: memory allocation error (line %d)",
				(__LINE__ - 2) );
		return 0;
	}

	return strlen(*buffer);
}

static int rds_descr(char **buffer)
{
	*buffer = strdup(hb_media_name);
	if (!*buffer) {
		PILCallLog(LOG, PIL_CRIT, "rds: memory allocation error (line %d)",
				(__LINE__ - 2) );
		return 0;
	}

	return strlen(*buffer);
}

static int rds_isping(void)
{
	return 0;
}

static int rds_init(void)
{
	struct servent *service;

	g_assert(OurImports != NULL);

	if (localrdsport <= 0) {
		const char *chport;
		if ((chport  = OurImports->ParamValue("rdsport")) != NULL) {
			if (sscanf(chport, "%d", &localrdsport) <= 0
			    || localrdsport <= 0) {
				PILCallLog(LOG, PIL_CRIT,
					"rds: bad port number %s", chport);
				return HA_FAIL;
			}
		}
	}

	/* No port specified in the configuration... */

	if (localrdsport <= 0) {
		/* If our service name is in /etc/services, then use it */
		if ((service=getservbyname(HA_SERVICENAME, "rds")) != NULL)
			localrdsport = ntohs(service->s_port);
		else
			localrdsport = UDPPORT;
	}
	return HA_OK;
}

/*
 *	Create new RDS/IP heartbeat object
 *	Name of interface and address are passed as parameters
 */
static struct hb_media*
rds_new(const char *intf)
{
	struct rds_private *ipi;
	struct hb_media *ret;

	rds_init();

	ipi = new_ip_interface(intf);
	if (!ipi) {
		PILCallLog(LOG, PIL_CRIT, "rds: interface [%s] does not exist", intf);
		return NULL;
	}
	ret = (struct hb_media*)MALLOC(sizeof(struct hb_media));
	if (!ret) {
		PILCallLog(LOG, PIL_CRIT, "rds: cannot alloc hb_media");
		goto out1;
	} else {
		memset(ret, 0, sizeof(*ret));
		ret->pd = (void*)ipi;

		ret->name = STRDUP(intf);
		if (!ret->name) {
			PILCallLog(LOG, PIL_CRIT, "rds: cannot strdup name");
			goto out2;
		}
	}
	return ret;
out2:
	FREE(ret);
out1:
	FREE(ipi->interface);
	FREE(ipi);
	return NULL;
}

/*
 *	Open RDS/IP unicast heartbeat interface
 */
static int rds_open(struct hb_media* mp)
{
	struct rds_private * ei;

	RDSASSERT(mp);
	ei = (struct rds_private*)mp->pd;

	ei->socket = HB_make_sock(mp);
	if (ei->socket < 0)
		return HA_FAIL;

	PILCallLog(LOG, PIL_INFO, "rds: started on %s %s:%d",
		ei->interface, inet_ntoa(ei->my_addr.sin_addr), localrdsport);
	return HA_OK;
}

/*
 *	Close RDS/IP unicast heartbeat interface
 */
static int rds_close(struct hb_media* mp)
{
	struct rds_private *ei;
	int rc = HA_OK;

	RDSASSERT(mp);
	ei = (struct rds_private*)mp->pd;

	if (ei->socket >= 0) {
		if (close(ei->socket) < 0) {
			rc = HA_FAIL;
		}
		ei->socket = -1;
	}
	return rc;
}


/*
 * Receive a heartbeat unicast packet from RDS interface
 */

char rds_pkt[MAXMSG];

static void *
rds_read(struct hb_media* mp, int *lenp)
{
	struct rds_private *ei;
	socklen_t addr_len;
	struct sockaddr_in their_addr;
	int numbytes;

	RDSASSERT(mp);
	ei = (struct rds_private*)mp->pd;

	addr_len = sizeof(struct sockaddr);
	if ((numbytes = recvfrom(ei->socket, rds_pkt, MAXMSG-1, 0,
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		if (errno != EINTR) {
			PILCallLog(LOG, PIL_CRIT, "rds: error receiving from socket: %s",
				strerror(errno));
		}
		return NULL;
	}
	if (numbytes == 0) {
		PILCallLog(LOG, PIL_CRIT, "rds: received zero bytes");
		return NULL;
	}
	if (numbytes > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "rds: %s maximum received message: %d bytes from %s",
			ei->interface, numbytes, inet_ntoa(their_addr.sin_addr));
		largest_msg_size = numbytes;
	}

	rds_pkt[numbytes] = EOS;

	if (DEBUGPKT) {
		PILCallLog(LOG, PIL_DEBUG, "rds: received %d byte packet from %s",
			numbytes, inet_ntoa(their_addr.sin_addr));
	}
	if (DEBUGPKTCONT) {
		PILCallLog(LOG, PIL_DEBUG, "%s", rds_pkt);
	}

	*lenp = numbytes +1;
	return rds_pkt;
}

/*
 * Send a heartbeat packet over unicast RDS/IP interface
 */

struct state_on_stack {
	struct hb_media *mp;
	char *peer;
	void *pkt;
	int len;
	int err_count;
};

static void rds_sendto_one(gpointer key, gpointer value, gpointer user_data)
{
	struct state_on_stack *s = user_data;
	struct sockaddr_in *addr = value;
	struct rds_private *ei = s->mp->pd;
	const char *this_peer = key;
	int rc;

	if (s->peer && strcmp(s->peer, this_peer)) {
		if (DEBUGPKT) {
			PILCallLog(LOG, PIL_DEBUG, "rds: %s != %s, NOT sending to %s",
					this_peer, s->peer, inet_ntoa(addr->sin_addr));
		}
		return;
	}

	rc = sendto(ei->socket, s->pkt, s->len, MSG_DONTWAIT, addr, sizeof(*addr));
	/* FIXME
	 * handle RDS specific meaning of error codes like EMSGSIZE, EAGAIN, ENOBUFS
	 */
	if (rc != s->len) {
		s->err_count++;
		if (!s->mp->suppresserrs) {
			PILCallLog(LOG, PIL_CRIT, "sendto(%s) failed: [%d] %s",
				inet_ntoa(addr->sin_addr), rc, strerror(errno));
		}
		return;
	}
	if (DEBUGPKT) {
		PILCallLog(LOG, PIL_DEBUG, "rds: sent %d bytes to %s", rc,
			inet_ntoa(addr->sin_addr));
	}
}

static int
rds_write(struct hb_media* mp, void *pkt, int len)
{
	struct state_on_stack s;
	struct rds_private *ei = mp->pd;
#if 0
	char node[64];
	char ns_len[3];
	char delim = EOS;
	char *dest = NULL;
#endif

	RDSASSERT(mp);
	s.mp = mp;
	s.peer = NULL;
	s.pkt = pkt;
	s.len = len;
	s.err_count = 0;

#if 0
	/* We assume that the F_TO field, if present, is always the first field
	 * in a message.  A follow-up commit to hb_msg_internal.c will actually
	 * assure that. */
	/* Unfortunately it is not that easy.
	 * Cluster wide sequence numbers (F_SEQ) will get out-of-sync, triggering
	 * rexmit. Unless we send "dummy" messages, or piggy-back some
	 * information about node-messages not sent to everyone to the next
	 * cluster wide message.  Impact on F_ORDERSEQ is even worse.
	 */
	if (*(const unsigned*)pkt == *(const unsigned *)MSG_START_NETSTRING) {
		int rc = sscanf((char*)pkt+4, "%2[0-9]:(0)dest=%63[^,]%c",
				ns_len, node, &delim);
		/* TOBEDONE if you are paranoid, you need to double check
		 * that this was correct netstring encoding, by checking the length */
		if (rc == 3 && delim == ',')
			dest = node;
	} else if (*(const unsigned*)pkt == *(const unsigned *)MSG_START) {
		int rc = sscanf((char*)pkt+4, "dest=%63[^\n]%c", node, &delim);
		if (rc == 2 && delim == '\n')
			dest = node;
	}
	if (dest) {
		if (DEBUGPKT) {
			PILCallLog(LOG, PIL_DEBUG, "rds: detected node message to %s", dest);
		}
		/* not yet enabled! s.peer = dest; */
	}
#endif

	g_hash_table_foreach(ei->peer_addresses, rds_sendto_one, &s);

	if (DEBUGPKTCONT) {
		PILCallLog(LOG, PIL_DEBUG, "%s", (const char*)pkt);
	}

	if (s.err_count >= ei->n_peers)
		return HA_FAIL;

	if (len > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "rds: %s maximum sent message: %d bytes",
			ei->interface, len);
		largest_msg_size = len;
	}
	return HA_OK;
}


/* if_getaddr gets the ip address from an interface
 * specified by name and places it in addr.
 * returns 0 on success and -1 on failure.
 */
static int
if_getaddr(const char *ifname, struct in_addr *addr)
{
	struct ifreq	if_info;
	int		j;
	int		maxtry = 120;
	gboolean	gotaddr = FALSE;
	int		err = 0;

	if (!addr) {
		return -1;
	}

	addr->s_addr = INADDR_ANY;

	memset(&if_info, 0, sizeof(if_info));
	if (ifname) {
		strncpy(if_info.ifr_name, ifname, IFNAMSIZ-1);
	}else{	/* ifname is NULL, so use any address */
		return 0;
	}

	if (Debug > 0) {
		PILCallLog(LOG, PIL_DEBUG, "looking up address for %s"
		,	if_info.ifr_name);
	}
	for (j=0; j < maxtry && !gotaddr; ++j) {
		int		fd;
		if ((fd=socket(AF_INET, SOCK_DGRAM, 0)) == -1)	{
			PILCallLog(LOG, PIL_CRIT, "Error getting socket");
			return -1;
		}
		if (ioctl(fd, SIOCGIFADDR, &if_info) >= 0) {
			gotaddr = TRUE;
		}else{
			err = errno;
			switch(err) {
				case EADDRNOTAVAIL:
					sleep(1);
					break;
				default:
					close(fd);
					goto getout;
			}
		}
		close(fd);
	}
getout:
	if (!gotaddr) {
		PILCallLog(LOG, PIL_CRIT
		,	"Unable to retrieve local interface address"
		" for interface [%s] using ioctl(SIOCGIFADDR): %s"
		,	ifname, strerror(err));
		return -1;
	}

	/*
	 * This #define w/void cast is to quiet alignment errors on some
	 * platforms (notably Solaris)
	 */
#define SOCKADDR_IN(a)        ((struct sockaddr_in *)((void*)(a)))

	memcpy(addr, &(SOCKADDR_IN(&if_info.ifr_addr)->sin_addr)
	,	sizeof(struct in_addr));

	return 0;
}

static void
adjust_socket_bufs(int sockfd, int bytes)
{
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUFFORCE, &bytes, sizeof(bytes));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, sizeof(bytes));
	getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, NULL);
	PILCallLog(LOG, PIL_INFO, "rds: set sndbuf to %d", bytes);
	getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, NULL);
	PILCallLog(LOG, PIL_INFO, "rds: set rcvbuf to %d", bytes);
}


/*
 * Set up socket for sending unicast RDS heartbeats
 */

static int HB_make_sock(struct hb_media *mp)
{
	int sockfd;
	struct rds_private *ei;

	RDSASSERT(mp);
	ei = (struct rds_private*)mp->pd;

	if ((sockfd = socket(AF_RDS, SOCK_SEQPACKET, 0)) < 0) {
		PILCallLog(LOG, PIL_CRIT, "rds: Error creating socket: %s",
			strerror(errno));
		return -1;
	}
	adjust_socket_bufs(sockfd, ei->n_peers * 512*1024);

	if (bind(sockfd, &ei->my_addr, sizeof(struct sockaddr_in)) < 0) {
		PILCallLog(LOG, PIL_CRIT, "rds: unable to bind socket: %s",
			strerror(errno));
		close(sockfd);
		return -1;
	}
	if (fcntl(sockfd,F_SETFD, FD_CLOEXEC) < 0) {
		PILCallLog(LOG, PIL_CRIT, "rds: error setting close-on-exec flag: %s",
			strerror(errno));
	}

	return sockfd;
}

static struct rds_private* new_ip_interface(const char *ifn)
{
	struct rds_private *ep;

	ep = MALLOC(sizeof(struct rds_private));
	if (!ep) {
		PILCallLog(LOG, PIL_CRIT, "rds: cannot alloc rds_private");
		return NULL;
	}
	memset(ep, 0, sizeof(*ep));	/* zero the struct */

	ep->interface = STRDUP(ifn);
	if (!ep->interface) {
		PILCallLog(LOG, PIL_CRIT, "rds: cannot strdup interface");
		goto out1;
	}

	if (if_getaddr(ep->interface, &ep->my_addr.sin_addr))
		goto out2;

	ep->my_addr.sin_family = AF_INET;		/* host byte order */
	ep->my_addr.sin_port = htons(localrdsport);	/* short, network byte order */
	ep->port = localrdsport;
	ep->socket = -1;

	return ep;

out2:
	FREE(ep->interface);
out1:
	FREE(ep);
	return NULL;
}
