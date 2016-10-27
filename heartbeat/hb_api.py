#!/usr/bin/python

'''Heartbeat related classes.

What we have here is a handful of classes related to the
heartbeat cluster membership services.

These classes are:
    ha_msg:  The heartbeat messaging class
    hb_api:  The heartbeat API class
 '''

__copyright__='''
Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
Licensed under the GNU GPL.
'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import types, string, os, sys
from UserDict import UserDict
import select
import socket
import struct
import grp

global debug_level
debug_level = 0
def dbg(level, *args):
	if level > debug_level:
		return
	print >> sys.stderr, "<%d>%s" % (level, " ".join(args))

'''
	"module" simple regex based netstring
	We don't need an arbitrary buffer based netstring parser,
	we only ever decode complete netstring messages of limitted size.
'''

import re
def netstring_encode(s):
    return "%i:%s," % (len(s), s)

def _netstring_decode(s):
	while len(s):
		m = re.match(r"(\d+):", s)
		if not m:
			raise ValueError("invalid size digit: expected '\d+:', but got '%c'" % s[0])

		l = len(m.group(0))
		n = int(m.group(1))
		if len(s) < n + l:
			raise ValueError("truncated input: expected %u bytes, only %u available" % (n, len(s)))
		if s[n+l] != ',':
			raise ValueError("invalid input: expected ',' terminator, but got '%c'" % s[n+l])
		v = s[l:n+l]
		s = s[n+l+1:]
		yield v


def netstring_decode(data):
	return list(_netstring_decode(data))

class ha_msg (UserDict): 

    '''ha_msg is the Heartbeat messaging class.  It is the bottle into
    which you put messages before throwing them out onto the sea
    of cluster :-)  Not surprisingly, it is also the bottle which you
    receive them in.  It is also the way you communicate with heartbeat
    itself using its API

    All heartbeat messages are name value pairs (~Python dicts)
    Not too surprisingly, this is much nicer in python than in 'C'

    These objects are the fundamental units of heartbeat communication,
    and also the fundamental units of communication with heartbeat itself
    (via the heartbeat API).

    This class is basically a restricted dictionary type with a few
    minor twists to make it fit a little better into the heartbeat
    message paradigm.

    These twists are:
        We only allow strings as names and values
        We require a particular canonical string representation
            so we can transport them compatibly on the network
        We allow a wide variety of __init__() and update() args
            including strings in our canonical network format
        See the update member function for more details.
        We are picky about what kinds of things you want to shove into
            our bottle.  Everything needs to be strings, and need to be
            somewhat restricted in content from the Python point of view.
            For example, no nulls, no newlines, etc.

    Constructor arguments:
        dictionaries, ha_msg objects, 2-element lists/tuples, files
	strings (in canonical msg format)

    Exceptions raised:

    ValueError:
       For every bad parameter we see, we raise a ValueError.
       This can happen when the string you've given us doesn't
       meet our expectations in various ways.  Be prepared to deal with it
       when you give us messages you can't guarantee are perfect.
    '''

    #	Field names start with F_...

    F_TYPE="t"
    F_ORIG="src"
    F_NODE="node"
    F_TO="dest"
    F_FROMID="from_id"
    F_FILTERMASK="fmask"
    F_IFNAME="ifname"
    F_NODENAME="node"
    F_NODETYPE="nodetype"
    F_TOID="to_id"
    F_PID="pid"
    F_STATUS="st"
    F_APIREQ="reqtype"
    F_APIRESULT="result"
    F_COMMENT="info"
    F_RESOURCES="rsc_hold"
    F_PNAME="pname"
    F_PVALUE="pvalue"

    #	Message types start with T_...

    T_APIREQ="hbapi-req"
    T_APIRESP="hbapi-resp"
    T_TESTREQ="cltest-req"
    T_TESTRSP="cltest-rsp"
    T_STATUS="status"
    T_NS_STATUS="NS_st"
    T_IFSTATUS="ifstat"

    #
    #   Things we need for making network-compatible strings
    #   from ha_msg objects
    #
    max_reprlen = 1024	# Maximum length string for an ha_msg
    startstr=">>>\n"
    endstr="<<<\n"
    endstr0="<<<\n\0"	# Bug to bug compatibility :-/
    start_netstr="###\n"
    end_netstr="%%%\n"
    __str__ = UserDict.__repr__	 # use default __str__ function


    def __init__(self, *args):

    	'''Initialize the ha_msg according to the parameters we're given'''

        self.data = {}
	for arg in args:
            self.update(arg)

    def update(self, *args):

        '''Update the message from info in our arguments
           We currently allow these kinds of arguments:
             dictionary, ha_msg, tuple, list, string, file...
	'''
#
#	It would be nice to check for type attributes rather than
#	for specific types...
#
	for arg in args:

            # Do we have a String?
            if isinstance(arg, types.StringType):
                self.fromstring(arg)

            # Do we have a 2-element Tuple/List?
            elif (isinstance(arg, types.TupleType)
            or    isinstance(arg, types.ListType)):

                if len(arg) != 2: raise ValueError("wrong size tuple/list")
                self[arg[0]] = arg[1]

            # Do we have a dictionary or ha_msg object?
            elif (isinstance(arg, types.DictType)
            or   (isinstance(arg, types.InstanceType)
                  and issubclass(arg.__class__, UserDict))):

                for key in arg.keys():
		    self[key] = arg[key]

            # How about a file?
            elif isinstance(arg, types.FileType):
    		self.fromfile(arg)
	    # or a socket?
	    elif isinstance(arg, socket.SocketType):
		self.fromsock(arg)
            else: 
	      raise ValueError("bad type in update")

#	I can imagine more validation being useful...
#	The strings have more constraints than this code enforces...
#	They can't contain NULLs, or \r or \n
#
#	The names should be legitimate environment var names
#	(for example, can't contain '=')
#	etc...

    def __setitem__(self, k, value):
        if (not isinstance(k, types.StringType)
        or  not isinstance(k, types.StringType)):
		raise ValueError("non-string data")
        self.data[k] = value

    def __repr__(self):

        '''Convert to the canonical network-format string
           that heartbeat expects us to use.
        '''

	ret = ha_msg.startstr
        for i in self.items():
            ret = ret + i[0] + "=" + i[1] + "\n"
	ret = ret + ha_msg.endstr

	if len(ret) <= ha_msg.max_reprlen:
            return ret
        raise ValueError("message length error")


    #   Convert from canonical-message-string to ha_msg

    def fromstring(self, s):

        '''Update an ha_msg from a string
           The string must be in our "well-known" network format
           (like comes from heartbeat or __repr__())
        '''

	if  (s[:len(ha_msg.start_netstr)] == ha_msg.start_netstr
	and  s[-len(ha_msg.end_netstr):] == ha_msg.end_netstr) :
		return self.from_netstring(s[len(ha_msg.start_netstr):-len(ha_msg.end_netstr)])

	#
	# It should start w/ha_msg.startstr, and end w/ha_msg.endstr
	#
	if  (s[:len(ha_msg.startstr)] != ha_msg.startstr
	or   (s[-len(ha_msg.endstr):] != ha_msg.endstr and
	      s[-len(ha_msg.endstr0):] != ha_msg.endstr0)) :
		raise ValueError("message format error")


        #
        # Split up the string into lines, and process each
	# line as a name=value pair
        #
	strings = s.split('\n')[1:-2]
        for astring in strings:
            # Update-from-list is handy here...
	    # FT_STRING, standard plain text string field
	    # in the "classic" (not netstring) message format,
	    # this is sent as, you guessed right, plain text string,
	    # no leading "(type)" indicator.
	    if astring[0] != "(":
		self.update(astring.split('=', 1))
	    # else: 
	    #   (1) FT_BINARY
	    #   (2) FT_STRUCT
	    #   (3) FT_LIST
	    #   (4) FT_COMPRESS
	    #   (5) FT_UNCOMPRESS
	    #   IGNORE THESE FOR NOW.

    def from_netstring(self, s):
	l = netstring_decode(s)
	for astring in iter(l):
	    if astring[:3] == "(0)":
		# FT_STRING, standard plain text string field
		self.update(astring[3:].split("=", 1))
	    # else: 
	    #   (1) FT_BINARY
	    #   (2) FT_STRUCT
	    #   (3) FT_LIST
	    #   (4) FT_COMPRESS
	    #   (5) FT_UNCOMPRESS
	    #   IGNORE THESE FOR NOW.
	    #	self.update(astring.split("=", 1))

    def fromfile(self, f):

        '''Read an ha_msg from a file.
           This means that we read from the file until we find an ha_msg
           string, then plop it into 'self'
        '''

        delimfound=0
        while not delimfound: 
            line = f.readline()
            if line == "" : raise ValueError("EOF")
            delimfound = (line == ha_msg.startstr)

        delimfound=0

        line="?"
        while not delimfound and line != "":
            line = f.readline()
            if line == "" : raise ValueError("EOF")
            delimfound = (line == ha_msg.endstr)
	    if not delimfound: self.update(line[:-1].split('=', 1))

    def fromsock(self, s):
	len_magic = ''
	len_magic = s.recv(8, socket.MSG_WAITALL)
	if len(len_magic) < 8:
		# should not happen, would have raised socket.error already
		raise ValueError("short recv expecting 8 byte header")
	(l, magic) = struct.unpack("II", len_magic)
	msg = s.recv(l, socket.MSG_WAITALL)
	dbg(2, "RECEIVED MESSAGE", msg)
	if len(msg) < l:
		raise ValueError("short recv expecting %u byte payload" % l)
	self.fromstring(msg)
	dbg(3, "PARSED AS: ", repr(self))

    def tosock(self, s):
        '''Send an ha_msg to a socket, and flush it.'''
	msg = repr(self)
	dbg(2, "SENDING", msg)
	s.sendall(struct.pack("II", len(msg), 0xabcd) + msg)
        return 1

class hb_api:
    '''The heartbeat API class.
    This interesting and useful class is a python client side implementation
    of the heartbeat API.  It allows one to inquire concerning the valid
    set of nodes and interfaces, and in turn allows one to inquire about the
    status of these things.  Additionally, it allows one to send messages to
    the cluster, and to receive messages from the cluster.
    '''
#
#	Probably the exceptions we trap should have messages that
#	go along with them, since they shouldn't happen.
#

#
#	Various constants that are part of the heartbeat API
#
    SIGNON="signon"
    SIGNOFF="signoff"
    SETFILTER="setfilter"
    SETSIGNAL="setsignal"
    NODELIST="nodelist"
    NODESTATUS="nodestatus"
    NODETYPE="nodetype"
    IFLIST="iflist"
    IFSTATUS="ifstatus"
    GETPARM="getparm"
    GETRESOURCES="getrsc"

    ActiveStatus="active"

    OK="OK"
    FAILURE="fail"
    BADREQ="badreq"
    MORE="ok/more"
    _pid=os.getpid()

    def __init__(self, debug=0):
	global debug_level
        self.SignedOn=0
        self.socket = None
        self.iscasual=1
        self.MsgQ = []
        self.Callbacks = {}
        self.NodeCallback = None
        self.IFCallback = None
	self.Nodes = None
	self.hbversion = None
	self.pacemaker = None
	debug_level = debug

    def __del__(self):
        '''hb_api class destructor.
        NOTE: If you're going to let an hb_api object go out of scope, and
        not sign off, then don't let it go out of scope from the highest
        level but instead make sure it goes out of scope from a function.
        This is because some of the classes this destructor needs may have
        already disappeared if you wait until the bitter end to __del__ us :-(
        '''
        dbg(1, "Destroying hb_api object")
        self.signoff()

    def __api_msg(self, msgtype):

        '''Create a standard boilerplate API message'''

	return ha_msg(
           { ha_msg.F_TYPE   : ha_msg.T_APIREQ,
             ha_msg.F_APIREQ : msgtype,
             ha_msg.F_PID    : repr(hb_api._pid),
             ha_msg.F_FROMID : self.OurClientID,
           })

    def __get_reply(self):

        '''Return the reply to the current API request'''

        try:
            while 1:
                reply = ha_msg(self.socket)
                if reply[ha_msg.F_TYPE] == ha_msg.T_APIRESP:
                    return reply
                # Not an API reply.  Queue it up for later...
                self.MsgQ.append(reply)

        except (KeyError,ValueError):
            return None

    def __CallbackCall(self, msg):
        '''Perform the callback calls (if any) associated with the given
           message.  We never do more than one callback per message.
           and we return true if we did any callbacks, and None otherwise.
        '''

        msgtype = msg[ha_msg.F_TYPE]

        if self.NodeCallback and (msgtype == ha_msg.T_STATUS
        or                        msgtype == ha_msg.T_NS_STATUS):
            node=msg[ha_msg.F_ORIG]
	    stat=msg[ha_msg.F_STATUS]
            self.NodeCallback[0](node, stat, self.NodeCallback[1])
            return 1

        if self.IFCallback and msgtype == ha_msg.T_IFSTATUS:
            node=msg[ha_msg.F_NODE]
	    iface=msg[ha_msg.F_IFNAME]
            stat=msg[ha_msg.F_STATUS]
            self.IFCallback[0](node, iface, stat, self.IFCallback[1])
            return 1

        if self.Callbacks.has_key(msgtype):
            entry = self.Callbacks[msgtype]
            entry[0](msg, entry[1])
            return 1

        return None

    def __read_hb_msg(self, blocking, timeout=0):

        '''Return the next message from heartbeat.'''

        if len(self.MsgQ) > 0:
            return self.MsgQ.pop(0)

	if timeout and not self.msgready(timeout=timeout):
	    return None
	elif not blocking and not self.msgready(timeout=0):
            return None

        # ok, if msgready returned True,
	# but we only have a partial message in the socket buffer,
	# and the socket has its default timeout of "None",
	# we will still potentially block "forever"...
	# but half-delivered messages "should not happen"...

        try:
            return ha_msg(self.socket)
        except (ValueError):
            return None


    def readmsg(self, blocking=False, timeout=0):

        '''Return the next message to the caller for which there were no active
           callbacks.  Call the callbacks for those messages which might
           have been read along the way that *do* have callbacks.
           Because this is Python, and this member function also replaces
           the 'rcvmsg' function in the 'C' code.
        '''

        while(1):
            rc=self.__read_hb_msg(blocking=blocking, timeout=timeout)

            if rc == None: return None

            if not self.__CallbackCall(rc):
                return rc

    def signoff(self):

        '''Sign off of the heartbeat API.'''

        if self.socket:
            msg = self.__api_msg(hb_api.SIGNOFF)
	    try:
		    msg.tosock(self.socket)
		    self.socket.close()
	    except socket.error, e:
		    # may already be closed by the remote side
		    pass
	    self.socket = None
        self.SignedOn=0

    def signon(self, service=None):

        '''Sign on to heartbeat (register as a client)'''
        hb_register_socket_name = "/var/run/heartbeat/register"

        if service == None:
            self.OurClientID = repr(hb_api._pid)
            self.iscasual = 1
        else:
            self.OurClientID = service
            self.iscasual = 0

        self.OurNode = os.uname()[1].lower()

	msg = hb_api.__api_msg(self, hb_api.SIGNON)
	msg.update({
	 "uid" : "%u" % os.getuid(),
	 "gid" : "%u" % os.getgid() })

        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(hb_register_socket_name);
        except socket.error, e:
            print >> sys.stderr, "connect(%s): %s" % (hb_register_socket_name, e)

        # Send the registration request
	msg.tosock(s)
	self.socket = s

        try:
            # Read the reply
            reply = self.__get_reply()

	    # Read the return code
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.OK :
		self.socket = s
                self.SignedOn=1
		if "hbversion" in reply:
			self.hbversion = reply["hbversion"]
		if "pacemaker" in reply:
			self.pacemaker = reply["pacemaker"]
                return 1
	    self.signoff()
            return None

        except (KeyError,ValueError,TypeError):
	    self.signoff()
            return None

    def setfilter(self, fmask):

        '''Set message reception filter mask
        This is the 'raw' interface.  I guess I should implement
        a higher-level one, too... :-)
        '''

        msg = hb_api.__api_msg(self, hb_api.SETFILTER)
        msg[ha_msg.F_FILTERMASK] = "%x" % fmask
	msg.tosock(self.socket)

        try:
            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.OK:
                return 1
            return None

        except (KeyError, ValueError):
            return None

    def setsignal(self, signal):

        '''Set message notification signal (0 to cancel)'''

        msg = hb_api.__api_msg(self, hb_api.SETSIGNAL)
        msg[ha_msg.F_SIGNAL] = "%d" % signal

	msg.tosock(self.socket)

        try:
            reply = self.__get_reply()

            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.OK :
                return 1
            return None

        except (KeyError, ValueError):
            return None

    def nodelist(self, usecache=False):

        '''Retrieve the list of nodes in the cluster'''

	if usecache and self.Nodes != None:
	    return self.Nodes

	self.Nodes = None
	Nodes = {}
	msg = hb_api.__api_msg(self, hb_api.NODELIST)

	msg.tosock(self.socket)

        try:
            while 1:
                reply = self.__get_reply()
                rc =  reply[ha_msg.F_APIRESULT]
                if rc != hb_api.OK and rc != hb_api.MORE:
                    return None

		nodename = reply[ha_msg.F_NODENAME]
		node = { "name" : nodename }
		if ha_msg.F_NODETYPE in reply:
		    node['type'] = reply[ha_msg.F_NODETYPE]
		if ha_msg.F_STATUS in reply:
		    node['status'] = reply[ha_msg.F_STATUS]

                Nodes[nodename] = node

                if rc == hb_api.OK :
		   self.Nodes = Nodes
                   return Nodes
                elif rc == hb_api.MORE:
                   continue
                else:
                  return None
        except (KeyError, ValueError):
            return None


    def iflist(self, node):

        '''Retrieve the list of interfaces to the given node'''

        Interfaces = {}
	msg = hb_api.__api_msg(self, hb_api.IFLIST)
        msg[ha_msg.F_NODENAME] = node

	msg.tosock(self.socket)

        try:
            while 1:
                reply = self.__get_reply()
                rc =  reply[ha_msg.F_APIRESULT]
                if rc != hb_api.OK and rc != hb_api.MORE :
                    return None

		ifname = reply[ha_msg.F_IFNAME]
		if ha_msg.F_STATUS in reply:
		    ifstat = reply[ha_msg.F_STATUS]
		else:
		    ifstat = None

		# Don't put duplicates in the list.
		# This would happen for example if you have
		# multiple ucast statements (one for each node)
		# on the same interface
		if not ifname in Interfaces:
		    Interfaces[ifname] = ifstat

                if rc == hb_api.OK :
                   return Interfaces
                elif rc == hb_api.MORE:
                   continue
                else:
                  return None
        except (KeyError, ValueError):
            return None


    def nodestatus(self, node):

        '''Retrieve the status of the given node'''

	msg = hb_api.__api_msg(self, hb_api.NODESTATUS)
	msg[ha_msg.F_NODENAME]=node


	msg.tosock(self.socket)

        try:

            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.FAILURE : return None

            return reply[ha_msg.F_STATUS]

        except (KeyError, ValueError):
            return None

    def getparm(self, pname):

        '''Retrieve the value of the named parameter'''

	msg = hb_api.__api_msg(self, hb_api.GETPARM)
	msg[ha_msg.F_PNAME]=pname

	msg.tosock(self.socket)

        try:

            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.FAILURE : return None

            return reply[ha_msg.F_PVALUE]

        except (KeyError, ValueError):
	    if pname == "pacemaker":
		return self.getparm("crm")
            return None

    def get_hbversion(self):
	if self.hbversion == None:
	    self.hbversion = self.getparm("hbversion")
	return self.hbversion

    def get_pacemaker(self):
	if self.pacemaker == None:
	    self.pacemaker = self.getparm("pacemaker")
	return self.pacemaker

    def getrsc(self):

        '''Retrieve the value of the named parameter'''

	msg = hb_api.__api_msg(self, hb_api.GETRESOURCES)

	msg.tosock(self.socket)

        try:
            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.FAILURE : return None

            return reply[ha_msg.F_RESOURCES]

        except (KeyError, ValueError):
            return None

    def nodetype(self, node):

        '''Retrieve the node-type of the given node ("normal" or "ping")'''

	msg = hb_api.__api_msg(self, hb_api.NODETYPE)
	msg[ha_msg.F_NODENAME]=node

	msg.tosock(self.socket)

        try:

            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.FAILURE : return None

            return reply[ha_msg.F_NODETYPE]

        except (KeyError, ValueError):
            return None

    def ifstatus(self, node, interface):

        '''Retrieve the status of the given interface on the given node'''

	msg = hb_api.__api_msg(self, hb_api.IFSTATUS)
	msg[ha_msg.F_NODENAME]=node
	msg[ha_msg.F_IFNAME]=interface

	msg.tosock(self.socket)

        try:

            reply = self.__get_reply()
            rc =  reply[ha_msg.F_APIRESULT]

            if rc == hb_api.FAILURE : return None

            return reply[ha_msg.F_STATUS]

        except (KeyError, ValueError):
            return None

    def cluster_config(self):

        '''Return the whole current cluster configuration.
        This call not present in the 'C' API.
        It could probably give a better structured return value.
        '''

        Nodes = self.nodelist()
        for (nodename, node) in Nodes.iteritems():
	    if not 'status' in node:
		node["status"] = self.nodestatus(nodename)
	    if not 'type' in node:
		node["type"] = self.nodetype(nodename)
            interfaces = self.iflist(nodename)
            for (ifname, ifstat) in interfaces.iteritems():
		if ifstat == None:
		   interfaces[ifname] = self.ifstatus(nodename, ifname)
            node["interfaces"] = interfaces
        return Nodes

    def nodes_with_status(self, status=None):
        '''Return the list of nodes with the given status.  Default status is
        hb_api.ActiveStatus (i.e., "active")
        '''
        if status == None: status=hb_api.ActiveStatus
        ret = []
        for (nodename, node) in self.nodelist().iteritems():
	    if "status" in node:
		nodestatus = node["status"]
	    else:
		nodestatus = self.nodestatus(nodename)
            if nodestatus == status:
                ret.append(nodename)
        return ret

    def get_inputfd(self):

        '''Return the input file descriptor associated with this object'''

        if not self.SignedOn: return None

        return self.socket.fileno()

    def fileno(self):
        return self.get_inputfd()

    def msgready(self, timeout=0):

        '''Returns TRUE if a message is waiting to be read.'''

        if len(self.MsgQ) > 0:
            return 1

        ifd = self.get_inputfd()

        inp, out, exc = select.select([ifd,], [], [], timeout)

        if len(inp) > 0 : return 1
        return None

    def sendclustermsg(self, origmsg):

        '''Send a message to all cluster members.

         This is not allowed for casual clients.'''
        # if not self.SignedOn or self.iscasual: return None

        msg =ha_msg(origmsg)
        msg[ha_msg.F_ORIG] = self.OurNode
	return msg.tosock(self.socket)

    def sendnodemsg(self, origmsg, node):

        '''Send a message to a specific node in the cluster.
         This is not allowed for casual clients.'''

        if not self.SignedOn or self.iscasual: return None

        msg = ha_msg(origmsg)
        msg[ha_msg.F_ORIG] = self.OurNode
        msg[ha_msg.F_TO] = node

	return msg.tosock(self.socket)


    def set_msg_callback(self, msgtype, callback, data):

        '''Define a callback for a specific message type.
           It returns the previous (callback,data) for
           that particular message type.
        '''

        if self.Callbacks.has_key(msgtype) :
            ret=self.Callbacks[msgtype]
        else:
            ret=None

        if callback == None :
            if self.Callbacks.has_key(msgtype) :
                del self.Callbacks[msgtype]
            return ret

        self.Callbacks[msgtype] = (callback, data)
        return ret

    def set_nstatus_callback(self, callback, data = None):

        '''Define a callback for node status changes.
           It returns the previous (callback,data) for
           the previous nstatus_callback.
        '''

        ret = self.NodeCallback
        if callback == None:
            self.NodeCallback = None
            return ret

        self.NodeCallback = (callback, data)
        return ret


    def set_ifstatus_callback(self, callback, data = None):

        '''Define a callback for interface status changes.
           It returns the previous (callback,data) for
           the previous ifstatus_callback.
        '''

        ret = self.IFCallback
        if callback == None:
            self.IFCallback = None
            return ret

        self.IFCallback = (callback, data)
        return ret

def nodestatus(node, stat, data):
	try:
		prev = data[node]["status"]
        except (KeyError,ValueError):
		prev = "?"
	print "*** NODE STATUS CHANGE: %s now %s, was %s" % (node, stat, prev)
	data[node]["status"] = stat

def ifstatus(node, iface, stat, data):
	try:
		prev = data[node]["interfaces"][iface]
        except (KeyError,ValueError):
		prev = "?"
	print "*** INTERFACE STATUS CHANGE: %s to %s now %s, was %s" % (iface, node, stat, prev)
	data[node]["interfaces"][iface] = stat

#
#   A little test code...
#
def main(argv):
    haclient_gid = grp.getgrnam("haclient")[2]
    os.setgid(haclient_gid)

    hb = hb_api(debug=0)
    if not hb.signon():
	print "Cannot signon to heartbeat API"
	exit(1)

    dbg(1, "Now signed on to heartbeat API...")
    dbg(1, "Asking for node and link status ...")

    # this is more a "status" than a "config",
    # but ...
    config = hb.cluster_config()

    print "Heartbeat Version:", hb.get_hbversion()
    pacemaker = hb.get_pacemaker()
    if pacemaker in ["false", "off", "no", "n", "0"]:
	    print "Resources:", hb.getrsc()
    else:
	    print "Pacemaker:", pacemaker

    print "\nNodes in cluster:", config.keys()
    for node in config.keys():
	 type = config[node]["type"]
	 state = config[node]["status"]
         print "\nStatus of %s node %s: %s" %  (type, node, state)
	 iflist = config[node]["interfaces"].keys()
         print "\tInterfaces to %s: %s" % (node, iflist)
         for intf in iflist:
             state = config[node]["interfaces"][intf]
             print "\tInterface %s to %s: %s" % (intf, node, state)

    if not '--monitor' in argv:
	return

    dbg(0, "\nListening for node or link status changes...\n")
    hb.set_nstatus_callback(nodestatus, config)
    hb.set_ifstatus_callback(ifstatus, config)
    while 1:
        msg = hb.readmsg(1)
        if msg:
            dbg(1, "Ignored incoming Message, no callback registered:", msg)

if __name__ == '__main__':
    try:
	main(sys.argv)
    except KeyboardInterrupt:
	pass
    except socket.error, e:
	print "Socket error: %s" % e
	exit(1)
