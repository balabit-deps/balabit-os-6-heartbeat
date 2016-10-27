/*
 * mcast6.c: implements hearbeat API for UDP IPv6 multicast communication
 *
 * Copyright (C) 2010 Lars Ellenberg <lars@linbit.com>
 * based on mcast6.c, which is
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 * Copyright (C) 2000 Chris Wright <chris@wirex.com>
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
 *
 */

#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifdef HAVE_SYS_SOCKIO_H
#	include <sys/sockio.h>
#endif

#include <HBcomm.h>

#define PIL_PLUGINTYPE          HB_COMM_TYPE
#define PIL_PLUGINTYPE_S        HB_COMM_TYPE_S
#define PIL_PLUGIN              mcast6
#define PIL_PLUGIN_S            "mcast6"
#define PIL_PLUGINLICENSE	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL	URL_LGPL
#include <pils/plugin.h>
#include <heartbeat.h>

static int largest_msg_size = 0;

struct mcast6_private {
	char    *interface;	/* Interface name */
	char    mcast6_s[64];	/* multicast address and port */
	char	port_s[8];	/* as read in from config */
	struct  sockaddr_in6   maddr;   /* multicast addr */
	struct  sockaddr_in6   saddr;   /* local addr to bind() to */
	int     rsocket;        /* Read-socket */
	int     wsocket;        /* Write-socket */
	u_char	hops;		/* TTL value for outbound packets */
	u_char	loop;		/* boolean, loop back outbound packets */
};


static int		mcast6_parse(const char* configline);
static struct hb_media * mcast6_new(const char * intf, const char *mcast6
			,	const char *port, u_char hops, u_char loop);
static int		mcast6_open(struct hb_media* mp);
static int		mcast6_close(struct hb_media* mp);
static void*		mcast6_read(struct hb_media* mp, int* lenp);
static int		mcast6_write(struct hb_media* mp, void* p, int len);
static int		mcast6_descr(char** buffer);
static int		mcast6_mtype(char** buffer);
static int		mcast6_isping(void);


static struct hb_media_fns mcast6Ops ={
	NULL,		/* Create single object function */
	mcast6_parse,	/* whole-line parse function */
	mcast6_open,
	mcast6_close,
	mcast6_read,
	mcast6_write,
	mcast6_mtype,
	mcast6_descr,
	mcast6_isping,
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static struct hb_media_imports*	OurImports;
static void*			interfprivate;

#define LOG	PluginImports->log
#define MALLOC	PluginImports->alloc
#define STRDUP  PluginImports->mstrdup
#define FREE	PluginImports->mfree

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);

	/*  Register our interface implementation */
	return imports->register_interface(us, PIL_PLUGINTYPE_S
	,	PIL_PLUGIN_S
	,	&mcast6Ops
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	interfprivate);
}


/* helper functions */
static int mcast6_make_receive_sock(struct hb_media* hbm);
static int mcast6_make_send_sock(struct hb_media * hbm);
static struct mcast6_private *
new_mcast6_private(const char *ifn, const char *mcast6, const char *port,
		u_char hops, u_char loop);
static int set_mcast6_if(int sockfd, char *ifname);
static int set_mcast6_loop(int sockfd, unsigned int loop);
static int set_mcast6_hops(int sockfd, int hops);
static int join_mcast6_group(int sockfd, struct in6_addr *addr, char *ifname);
static int is_valid_dev(const char *dev);
static int is_valid_mcast6_addr(const char *addr);
static int get_hops(const char *hops, u_char *t);
static int get_loop(const char *loop, u_char *l);


#define		ISMCASTOBJECT(mp) ((mp) && ((mp)->vf == (void*)&mcast6Ops))
#define		MCASTASSERT(mp)	g_assert(ISMCASTOBJECT(mp))

static int
mcast6_mtype(char** buffer)
{
	*buffer = STRDUP(PIL_PLUGIN_S);
	if (!*buffer) {
		return 0;
	}

	return STRLEN_CONST(PIL_PLUGIN_S);
}

static int
mcast6_descr(char **buffer)
{
	const char cret[] = "UDP/IP multicast";
	*buffer = STRDUP(cret);
	if (!*buffer) {
		return 0;
	}

	return STRLEN_CONST(cret);
}

static int
mcast6_isping(void)
{
	/* nope, this is not a ping device */
	return 0;
}

/* mcast6_parse will parse the line in the config file that is
 * associated with the media's type (hb_dev_mtype).  It should
 * receive the rest of the line after the mtype.  And it needs
 * to call hb_dev_new, add the media to the list of available media.
 *
 * So in this case, the config file line should look like
 * mcast6 [device] [mcast6 group] [port] [mcast6 hops] [mcast6 loop]
 * for example (using link-local scope with some "transient" group):
 * mcast6 eth0 ff12::1:2:3:4 694 1 0
 */
#define GET_NEXT_TOKEN(bp, token) do {           \
        int toklen;                              \
        bp += strspn(bp, WHITESPACE);            \
        toklen = strcspn(bp, WHITESPACE);        \
        strncpy(token, bp, toklen);              \
        bp += toklen;                            \
        token[toklen] = EOS;                     \
} while(0)

static int
mcast6_parse(const char *line)
{
	const char *		bp = line;
	char			dev[MAXLINE];
	char			mcast6[MAXLINE];
	char			port[MAXLINE];
	char			token[MAXLINE];
	u_char			hops = 10;	/* Bogus */
	u_char			loop = 10;	/* Bogus */
	struct hb_media *	mp;

	GET_NEXT_TOKEN(bp, dev);
	if (*dev == EOS) {
		PILCallLog(LOG, PIL_CRIT, "mcast6 statement without device");
		return HA_FAIL;
	}

	if (!is_valid_dev(dev)) {
		PILCallLog(LOG, PIL_CRIT, "mcast6 device [%s] is invalid or not set up properly", dev);
		return HA_FAIL;
	}

	GET_NEXT_TOKEN(bp, mcast6);
	if (*mcast6 == EOS)  {
		PILCallLog(LOG, PIL_CRIT, "mcast6 [%s] missing mcast6 address", dev);
		return(HA_FAIL);
	}
	if (!is_valid_mcast6_addr(mcast6)) {
		PILCallLog(LOG, PIL_CRIT, " mcast6 [%s] bad addr [%s]", dev, mcast6);
		return(HA_FAIL);
	}

	GET_NEXT_TOKEN(bp, port);

	if (*port == EOS)  {
		PILCallLog(LOG, PIL_CRIT, "mcast6 [%s] missing port", dev);
		return(HA_FAIL);
	}
	/* further validation on the port and mcast6 will be done with getaddrinfo later */

	/* hops */
	GET_NEXT_TOKEN(bp, token);
	if (*token == EOS)  {
		PILCallLog(LOG, PIL_CRIT, "mcast6 [%s] missing hops", dev);
		return(HA_FAIL);
	}
	if (get_hops(token, &hops) < -1 || hops > 4) {
		PILCallLog(LOG, PIL_CRIT, " mcast6 [%s] bad hops [%d]", dev, hops);
		return HA_FAIL;
	}

	/* loop */
	GET_NEXT_TOKEN(bp, token);
	if (*token == EOS)  {
		PILCallLog(LOG, PIL_CRIT, "mcast6 [%s] missing loop", dev);
		return(HA_FAIL);
	}
	if (get_loop(token, &loop) < 0 ||	loop > 1) {
		PILCallLog(LOG, PIL_CRIT, " mcast6 [%s] bad loop [%d]", dev, loop);
		return HA_FAIL;
	}

	if ((mp = mcast6_new(dev, mcast6, port, hops, loop)) == NULL) {
		return(HA_FAIL);
	}
	OurImports->RegisterNewMedium(mp);

	return(HA_OK);
}

/*
 * Create new UDP/IPv6 multicast heartbeat object
 * pass in name of interface, multicast address, port, multicast
 * hops, and multicast loopback value as parameters.
 * This should get called from hb_dev_parse().
 */
static struct hb_media *
mcast6_new(const char * intf, const char *mcast6, const char *port,
		    u_char hops, u_char loop)
{
	struct mcast6_private*	mcp;
	struct hb_media *	ret;

	/* create new mcast6_private struct...hmmm...who frees it? */
	mcp = new_mcast6_private(intf, mcast6, port, hops, loop);
	if (mcp == NULL) {
		PILCallLog(LOG, PIL_WARN, "Error creating mcast6_private(%s, %s, %s, %d, %d)",
			 intf, mcast6, port, hops, loop);
		return(NULL);
	}
	ret = (struct hb_media*) MALLOC(sizeof(struct hb_media));
	if (ret != NULL) {
		char * name;
		memset(ret, 0, sizeof(*ret));
		ret->pd = (void*)mcp;
		name = STRDUP(intf);
		if (name != NULL) {
			ret->name = name;
		}
		else {
			FREE(ret);
			ret = NULL;
		}

	}
	if(ret == NULL) {
		FREE(mcp->interface);
		FREE(mcp);
	}
	return(ret);
}

/*
 *	Open UDP/IP multicast heartbeat interface
 */
static int
mcast6_open(struct hb_media* hbm)
{
	struct mcast6_private * mcp;

	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	if ((mcp->wsocket = mcast6_make_send_sock(hbm)) < 0) {
		return(HA_FAIL);
	}
	if (Debug) {
		PILCallLog(LOG, PIL_DEBUG
		,	"%s: write socket: %d"
		,	__FUNCTION__, mcp->wsocket);
	}
	if ((mcp->rsocket = mcast6_make_receive_sock(hbm)) < 0) {
		mcast6_close(hbm);
		return(HA_FAIL);
	}
	if (Debug) {
		PILCallLog(LOG, PIL_DEBUG
		,	"%s: read socket: %d"
		,	__FUNCTION__, mcp->rsocket);
	}

	PILCallLog(LOG, PIL_INFO, "UDP multicast heartbeat started for [%s]:%s "
		"on interface %s (hops=%d loop=%d)" ,
		mcp->mcast6_s, mcp->port_s, mcp->interface, mcp->hops, mcp->loop);

	return(HA_OK);
}

/*
 *	Close UDP/IP multicast heartbeat interface
 */
static int
mcast6_close(struct hb_media* hbm)
{
	struct mcast6_private * mcp;
	int	rc = HA_OK;

	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	if (mcp->rsocket >= 0) {
		if (Debug) {
			PILCallLog(LOG, PIL_DEBUG
			,	"%s: Closing socket %d"
			,	__FUNCTION__, mcp->rsocket);
		}
		if (close(mcp->rsocket) < 0) {
			rc = HA_FAIL;
		}
		mcp->rsocket = -1;
	}
	if (mcp->wsocket >= 0) {
		if (Debug) {
			PILCallLog(LOG, PIL_DEBUG
			,	"%s: Closing socket %d"
			,	__FUNCTION__, mcp->wsocket);
		}
		if (close(mcp->wsocket) < 0) {
			rc = HA_FAIL;
		}
		mcp->rsocket = -1;
	}
	return(rc);
}

/*
 * Receive a heartbeat multicast packet from UDP interface
 */

char			mcast6_pkt[MAXMSG];
static void *
mcast6_read(struct hb_media* hbm, int *lenp)
{
	struct mcast6_private *	mcp;
	socklen_t		addr_len = sizeof(struct sockaddr);
	struct sockaddr_in	their_addr; /* connector's addr information */
	int	numbytes;

	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	if ((numbytes=recvfrom(mcp->rsocket, mcast6_pkt, MAXMSG-1, 0
	,	(struct sockaddr *)&their_addr, &addr_len)) < 0) {
		if (errno != EINTR) {
			PILCallLog(LOG, PIL_CRIT, "Error receiving from socket: %s"
			    ,	strerror(errno));
		}
		return NULL;
	}
	/* Avoid possible buffer overruns */
	mcast6_pkt[numbytes] = EOS;

	if (numbytes > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "mcast6: maximum received message: %d bytes from %s", numbytes, mcp->mcast6_s);
		largest_msg_size = numbytes;
	}
	if (Debug >= PKTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "got %d byte packet from %s"
		    ,	numbytes, inet_ntoa(their_addr.sin_addr));
	}
	if (Debug >= PKTCONTTRACE && numbytes > 0) {
		PILCallLog(LOG, PIL_DEBUG, "%s", mcast6_pkt);
	}

	*lenp = numbytes + 1 ;

	return mcast6_pkt;;
}

/*
 * Send a heartbeat packet over multicast UDP/IP interface
 */

static int
mcast6_write(struct hb_media* hbm, void *pkt, int len)
{
	struct mcast6_private *	mcp;
	int			rc;

	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	rc = sendto(mcp->wsocket, pkt, len, 0
	,	(struct sockaddr *)&mcp->maddr, sizeof(struct sockaddr_in6));
	if (rc != len) {
		if (!hbm->suppresserrs) {
			PILCallLog(LOG, PIL_CRIT
			,	"%s: Unable to send " PIL_PLUGINTYPE_S " packet %s[%s]:%s len=%d [%d]: %s"
			,	__FUNCTION__, mcp->interface, mcp->mcast6_s, mcp->port_s
			,	len, rc, strerror(errno));
		}
		return(HA_FAIL);
	}

	if (len > largest_msg_size) {
		PILCallLog(LOG, PIL_DEBUG, "mcast6: maximum sent message: %d bytes to %s", rc, mcp->mcast6_s);
		largest_msg_size = len;
	}

	if (Debug >= PKTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "sent %d bytes to %s", rc, mcp->mcast6_s);
	}
	if (Debug >= PKTCONTTRACE) {
		PILCallLog(LOG, PIL_DEBUG, "%s", (const char *)pkt);
	}
	return(HA_OK);
}

static void
adjust_socket_bufs(int sockfd, int bytes)
{
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	/* FIXME error handling, logging */
}

/*
 * Set up socket for sending multicast UDP heartbeats
 */

static int
mcast6_make_send_sock(struct hb_media * hbm)
{
	int sockfd;
	struct mcast6_private * mcp;
	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		PILCallLog(LOG, PIL_WARN, "Error getting socket: %s", strerror(errno));
		return(sockfd);
	}
	adjust_socket_bufs(sockfd, 1024*1024);

	if (set_mcast6_if(sockfd, mcp->interface) < 0) {
		PILCallLog(LOG, PIL_WARN, "Error setting outbound mcast6 interface: %s", strerror(errno));
	}

	if (set_mcast6_loop(sockfd, mcp->loop) < 0) {
		PILCallLog(LOG, PIL_WARN, "Error setting outbound mcast6 loopback value: %s", strerror(errno));
	}

	if (set_mcast6_hops(sockfd, mcp->hops) < 0) {
		PILCallLog(LOG, PIL_WARN, "Error setting outbound mcast6 hops: %s", strerror(errno));
	}

	if (fcntl(sockfd,F_SETFD, FD_CLOEXEC)) {
		PILCallLog(LOG, PIL_WARN, "Error setting the close-on-exec flag: %s", strerror(errno));
	}
	return(sockfd);
}

/*
 * Set up socket for listening to heartbeats (UDP multicasts)
 */

#define	MAXBINDTRIES	50
static int
mcast6_make_receive_sock(struct hb_media * hbm)
{
	struct mcast6_private * mcp;
	int	sockfd;
	int	bindtries;
	int	boundyet=0;
	int	one=1;
	int	rc;
	int	error=0;

	MCASTASSERT(hbm);
	mcp = (struct mcast6_private *) hbm->pd;

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		PILCallLog(LOG, PIL_CRIT, "Error getting socket");
		return -1;
	}
	/* set REUSEADDR option on socket so you can bind a multicast */
	/* reader to multiple interfaces */
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)) < 0){
		PILCallLog(LOG, PIL_CRIT, "Error setsockopt(SO_REUSEADDR)");
	}
	adjust_socket_bufs(sockfd, 1024*1024);

	/* ripped off from udp.c, if we all use SO_REUSEADDR */
	/* this shouldn't be necessary  */
	/* Try binding a few times before giving up */
	/* Sometimes a process with it open is exiting right now */

	for(bindtries=0; !boundyet && bindtries < MAXBINDTRIES; ++bindtries) {
		rc = bind(sockfd, (void*)&mcp->saddr, sizeof(mcp->saddr));
		error = errno;
		if (rc==0) {
			boundyet=1;
		} else if (rc == -1) {
			if (error == EADDRINUSE) {
				PILCallLog(LOG, PIL_CRIT, "Can't bind (EADDRINUSE), "
					"retrying");
				sleep(1);
			} else	{
			/* don't keep trying if the error isn't caused by */
			/* the address being in use already...real error */
				break;
			}
		}
	}
	if (!boundyet) {
		if (error == EADDRINUSE) {
			/* This happens with multiple udp or ppp interfaces */
			PILCallLog(LOG, PIL_INFO
			,	"Someone already listening on port %s [%s]"
			,	mcp->port_s
			,	mcp->interface);
			PILCallLog(LOG, PIL_INFO, "multicast read process exiting");
			close(sockfd);
			cleanexit(0);
		} else {
			PILCallLog(LOG, PIL_WARN, "Unable to bind socket to %s %s. Giving up: %s",
				mcp->mcast6_s, mcp->port_s, strerror(errno));
			close(sockfd);
			return(-1);
		}
	}
	/* join the multicast group...this is what really makes this a */
	/* multicast reader */
	if (join_mcast6_group(sockfd, &mcp->maddr.sin6_addr, mcp->interface) == -1) {
		char buf[/* 16 * 3 + some */ 64];
		PILCallLog(LOG, PIL_CRIT, "Can't join multicast group %s on interface %s"
		,	inet_ntop(AF_INET6, &mcp->maddr.sin6_addr, buf, sizeof(buf))
		,	mcp->interface);
		PILCallLog(LOG, PIL_INFO, "multicast read process exiting");
		close(sockfd);
		cleanexit(0);
	}
	if (ANYDEBUG) {
		PILCallLog(LOG, PIL_DEBUG,
			"Successfully joined multicast group %s on interface %s",
			mcp->mcast6_s, mcp->interface);
	}

	if (fcntl(sockfd,F_SETFD, FD_CLOEXEC)) {
		PILCallLog(LOG, PIL_WARN, "Error setting the close-on-exec flag: %s", strerror(errno));
	}
	return(sockfd);
}

static struct mcast6_private *
new_mcast6_private(const char *ifn, const char *mcast6, const char *port,
		u_char hops, u_char loop)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct mcast6_private *mcp;
	int error;

	mcp = MALLOCT(struct mcast6_private);
	if (mcp == NULL)  {
		return NULL;
	}
	memset(mcp, 0, sizeof(*mcp));

	mcp->interface = (char *)STRDUP(ifn);
	if(mcp->interface == NULL) {
		FREE(mcp);
		return NULL;
	}

	/* mcast group destination address */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(mcast6, port, &hints, &res);
	if (error) {
		PILCallLog(LOG, PIL_CRIT, "getaddrinfo([%s]:%s): %s",
			mcast6, port, gai_strerror(error));
		goto getout;
	}
	memcpy(&mcp->maddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	/* store canonicalized input as char* again. */
	inet_ntop(AF_INET6, &mcp->maddr.sin6_addr,
		mcp->mcast6_s, sizeof(mcp->mcast6_s));
	/* byte order! */
	sprintf(mcp->port_s, "%u", ntohs(mcp->maddr.sin6_port));

	/* local address to bind() to, results usually in [::]:someport */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(NULL, port, &hints, &res);
	if (error) {
		PILCallLog(LOG, PIL_CRIT, "getaddrinfo([::]:%s): %s",
			port, gai_strerror(error));
		goto getout;
	}
	memcpy(&mcp->saddr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	mcp->wsocket = -1;
	mcp->rsocket = -1;
	mcp->hops = hops;
	mcp->loop = loop;

	return mcp;

getout:
	FREE(mcp->interface);
	FREE(mcp);
	return NULL;
}

/* set_mcast6_loop takes a boolean flag, loop, which is useful on
 * a writing socket.  with loop enabled (the default on a multicast socket)
 * the outbound packet will get looped back and received by the sending
 * interface, if it is listening for the multicast group and port that the
 * packet was sent to.  Returns 0 on success -1 on failure.
 */
static int set_mcast6_loop(int sockfd, unsigned int loop)
{
	loop = !!loop;
	return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
}

/* set_mcast6_hops will set the multicast hop limit for the writing socket.
 * the socket default is hop=-1 (route default).
 * The hop is used to limit the scope of the packet and can range from 0-255.
 * Returns 0 on success -1 on failure.
 */
static int
set_mcast6_hops(int sockfd, int hops)
{
	return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
}

/*
 * set_mcast6_if takes the name of an interface (i.e. eth0) and then
 * sets that as the interface to use for outbound multicast traffic.
 * If ifname is NULL, then it the OS will assign the interface.
 * Returns 0 on success -1 on faliure.
 */
static int
set_mcast6_if(int sockfd, char *ifname)
{
	int rc;

	rc = if_nametoindex(ifname);
	if (rc == 0)
		return -1;

	return setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF
	,	&rc, sizeof(rc));
}

/* join_mcast6_group is used to join a multicast group.  the group is
 * specified by an IPv6 multicast group address in the in_addr
 * structure passed in as a parameter.  The interface name can be used
 * to "bind" the multicast group to a specific interface (or any
 * interface if ifname is NULL);
 * returns 0 on success, -1 on failure.
 */
static int
join_mcast6_group(int sockfd, struct in6_addr *addr, char *ifname)
{
	struct ipv6_mreq	mreq6;

	memset(&mreq6, 0, sizeof(mreq6));
	memcpy(&mreq6.ipv6mr_multiaddr, addr, sizeof(struct in6_addr));

	if (ifname) {
		mreq6.ipv6mr_interface = if_nametoindex(ifname);
	}
	return setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6));
}

/* returns true or false */
static int
is_valid_dev(const char *dev)
{
	int rc=0;
	if (dev) {
		if (if_nametoindex(dev) > 0)
			rc = 1;
	}
	return rc;
}

/* returns true or false */
static int
is_valid_mcast6_addr(const char *addr)
{
	unsigned char mc_addr[sizeof(struct in6_addr)];

	if (inet_pton(AF_INET6, addr, &mc_addr) <= 0)
		return 0;

	/* http://tools.ietf.org/html/rfc3513#section-2.7 */
	if (mc_addr[0] != 0xff)
		return 0;

	/* flags. the 0x10 bit marks "transient" */
	if ((mc_addr[1] & 0xe0) != 0)
		return 0;

	/* scope */
	switch (mc_addr[1] & 0x0f) {
	case 0x0: return 0;	/* reserved */
	/* heartbeats on interface-local scope are not useful. */
	case 0x1: return 0;
	case 0x2:  break; /* link-local scope */
	case 0x3: return 0;	/* reserved */
	case 0x4:  break; /* admin-local scope */
	case 0x5:  break; /* site-local scope */
	case 0x6: return 0;	/* (unassigned) */
	case 0x7: return 0;	/* (unassigned) */
	case 0x8:  break; /* organization-local scope */
	case 0x9: return 0;	/* (unassigned) */
	case 0xA: return 0;	/* (unassigned) */
	case 0xB: return 0;	/* (unassigned) */
	case 0xC: return 0;	/* (unassigned) */
	case 0xD: return 0;	/* (unassigned) */
	/* heartbeats SHALL NOT be in the global scope */
	case 0xE: return 0;
	case 0xF: return 0;	/* reserved */
	}

	/* all trailing zeros? reserved. */
	if (!memcmp(mc_addr+2,
		"\0\0" "\0\0\0\0" "\0\0\0\0" "\0\0\0\0", 14))
		return 0;

	/* still here? plausibility check passed */
	return 1;
}

/* returns hops on succes, -2 on failure */
static int
get_hops(const char *hops, u_char *t)
{
	/* not complete yet */
	*t=(u_char)atoi(hops);
	return 0;
}

/* returns loop on success, -1 on failure */
static int
get_loop(const char *loop, u_char *l)
{
	/* not complete yet */
	*l=(u_char)atoi(loop);
	return 0;
}

