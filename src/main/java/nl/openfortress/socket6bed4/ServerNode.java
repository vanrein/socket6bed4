package nl.openfortress.socket6bed4;


import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.SocketException;
import java.io.IOException;
import java.util.Arrays;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;


/** Each ServerNode instance serves a connection to a particular 6bed4
 * tunnel server.  This is reflected by its superclass, which is the
 * principal address serviced -- the IPv4 address and UDP port for the
 * server.
 *
 * As part of the service for a node, there is a neighbor cache.  This
 * may be compared to having a per-network neighbor cache as part of
 * an operating system.  Lookups may lead to more direct routes than
 * would otherwise be possible.
 *
 * TODO: Hook up handle_4to6/handle_6to4 methods with receive/send.
 * TODO: Handle IPv6 addr chg by throwing an IOException subclass.
 * TODO: Establish NeighborCache with lladdr_6bed4, somehow.
 */
public class ServerNode
extends DatagramSocket {

	private int usecount = 0;
	protected InetSocketAddress tunserver;
	protected NeighborCache ngbcache;
	protected Inet6Address sharedAddress;
	private Maintainer maintainer;
	private Worker worker;
	BlockingQueue<DatagramPacket> udp_clients [];
	static byte local_address [] = new byte [16];

	/** Create a connection to a 6bed4 tunnel server, and keep it active.
	 */
	public ServerNode (InetSocketAddress isa)
	throws SocketException {
		super ();
		tunserver = isa;
		maintainer = new Maintainer (this);
		worker = new Worker (this);
		udp_clients = new BlockingQueue [65536];
	}

	/** Create a connection to a 6bed4 tunnel server, and keep it active.
	 * This constructor binds locally to the given UDP port, if possible.
	 * This may provide a more predictable IPv6 address, but that depends
	 * on your networking setup.  If you are behind NAT, and/or someone
	 * else is already using the port you will still have a different IPv6
	 * address provided by the 6bed4 server, because it "sees" you on
	 * another UDP port at the outside of NAT.  NAT is NAsTy, we know.
	 * Things may improve when you setup port forwarding, but that would
	 * involve fixating the LAN host that can run this ServerNode at the
	 * given IPv6 address.  And again, it would depend on your NAT.
	 */
	public ServerNode (InetSocketAddress isa, int port)
	throws SocketException {
		super (port);
		tunserver = isa;
		maintainer = new Maintainer (this);
		worker = new Worker (this);
		udp_clients = new BlockingQueue [65536];
	}


	/** Teardown the connection to a 6bed4 tunnel server.
	 */
	public void stop () {
		worker.interrupt ();
		maintainer.interrupt ();
		if (ngbcache != null) {
			ngbcache.cleanup ();
			ngbcache = null;  /* Intended exceptions on continued use */
		}
	}

	/** Increment the use counter */
	public synchronized void useMore () {
		if (usecount++ == 0) {
			maintainer.start ();
			worker.start ();
		}
	}

	/** Decrement the use counter, return if it is now useless */
	public synchronized boolean useLess () {
		if (--usecount == 0) {
			maintainer.interrupt ();
			worker.interrupt ();
			return true;
		}
		return false;
	}


	/* Register a UDP client for a given port on the default
	 * IPv6 address as handed out by getDefault6bed4Address ().
	 * This is a claim to that port, and a SocketException is
	 * raised if it is not available.
	 */
	public void registerDatagramClient (int port)
	throws SocketException {
		synchronized (udp_clients) {
			if (udp_clients [port] != null) {
				throw new SocketException ("port taken");
			}
			udp_clients [port] = new ArrayBlockingQueue<DatagramPacket> (10);
		}
	}

	/* Unregister a client from a port that it has claimed.
	 */
	public void unregisterDatagramClient (int port)
	throws SocketException {
		synchronized (udp_clients) {
			if (udp_clients [port] == null) {
				throw new SocketException ("port not in use");
			}
			//TODO// possibly cleanup the Queue before letting go
			udp_clients [port] = null;
		}
	}

	/** Return the shared 6bed4 address, usable for anyone who
	 * wants to allocate ports for UDP/TCP through either a
	 * Socket6bed4 or a DatagramSocket6bed4.  This routine will
	 * block until an address has been obtained.
	 *
	 * To allocate recipients on the shared address, use
	 * registerDatagramClient(port) and, hopefully one day,
	 * registerStreamClient(port).  Raw access is not possible
	 * with this address; for that, use getUnique6bed4Address()
	 * as long as supply lasts.
	 */
	public Inet6Address getShared6bed4Address () {
		synchronized (maintainer) {
			while (sharedAddress == null) {
				try {
					maintainer.wait ();
				} catch (InterruptedException ie) {
					return null;
				}
			}
		}
		return sharedAddress;
	}

	/** Return a unique 6bed4 address, which is available for
	 * raw communication over IPv6.  Return null if no addresses
	 * are available anymore.
	 * Addresses returned from this function can be used as
	 * raw sockets.  They share the communication channel setup
	 * for getShared6bed4Address() but the contents of the IPv6
	 * packet will not be implemented, but rather relayed
	 * directly to the provided BlockingQueue instance.
	 * TODO: Sending, NxtHdr, and how to deal with security.
	 * TODO: Implement.  Consider security implications.
	 */
	public synchronized Inet6Address getUnique6bed4Address (BlockingQueue<byte[]> recv_TODO_OR_KEEP_INTERNAL) {
		//TODO// Register the address in the ConnectionPool so getServerNode() will work!
		return null;
	}

	/** Pull an element from the BlockingQueue for the given
	 * Datagram port.  Block if no input is available.
	 * The timeout value is in milli-seconds, zero
	 * representing infinity (just as with setSoTimeout).
	 */
	public DatagramPacket receive_datagram (int port, int timeout)
	throws SocketException {
		if (udp_clients [port] == null) {
			throw new SocketException ("port is not allocated");
		}
		try {
			if (timeout > 0) {
				return udp_clients [port].poll (timeout, TimeUnit.MILLISECONDS);
			} else {
				return udp_clients [port].take ();
			}
		} catch (InterruptedException ie) {
			return null;
		}
	}

	/** Acknowledge a playful exchange to the Neighbor Cache.
	 * This is a complex protocol, involving an interaction
	 * with the application layer, to confirm initial messages
	 * that support resends.  Please see the documentation in
	 * NeighborCache and DatagramSocket6bed4 for details.
	 */
	public void acknowledge_playful (byte addr[], int ofs) {
		if ((ngbcache != null) && (ofs + 16 <= addr.length)) {
			ngbcache.received_peer_direct_acknowledgement (addr, ofs, true);
		}
	}

	/** Lookup a neighbor.  Forwards to NeighborCache.
	 */
	public InetSocketAddress lookup_neighbor (Inet6Address ia, boolean playful) {
		while (ngbcache == null) {
			synchronized (maintainer) {
				try {
					maintainer.wait ();
				} catch (InterruptedException ie) {
					return null;
				}
			}
		}
		return ngbcache.lookup_neighbor (ia.getAddress (), 0, playful);
	}


	public void handle_4to6_nd (byte pkt [], int pktlen, SocketAddress src)
	throws IOException, SocketException {
		if (Utils.checksum_icmpv6 (pkt, 0) != Utils.fetch_net16 (pkt, Utils.OFS_ICMP6_CSUM)) {
			// Checksum is off
			return;
		}
		switch (pkt [Utils.OFS_ICMP6_TYPE]) {
		//
		// Handle Router Solicitation by dropping it -- this is a peer, not a router
		case Utils.ND_ROUTER_SOLICIT:
			return;
		//
		// Handle Router Advertisement as an addressing offering -- but validate the sender
		case Utils.ND_ROUTER_ADVERT:
			if (pktlen < 40 + 16 + 16) {
				// Too short to contain IPv6, ICMPv6 RtrAdv and Prefix Option
				return;
			}
			if ((pkt [Utils.OFS_ICMP6_DATA+1] & 0x80) != 0x00) {
				// Indecent proposal to use DHCPv6 over 6bed4
				return;
			}
			if (Utils.memdiff_addr (pkt, Utils.OFS_IP6_SRC, Utils.router_linklocal_address, 0)) {
				// Sender is not 0xfe80::/128
				return;
			}
			if (Utils.memdiff_halfaddr (pkt, Utils.OFS_IP6_DST, Utils.router_linklocal_address, 0)) {
				// Receiver address is not 0xfe80::/64
				return;
			}
			//TODO// Check if offered address looks like a multicast-address (MAC byte 0 is odd)
			//TODO// Check Secure ND on incoming Router Advertisement?
			//
			// Having validated the Router Advertisement, process its contents
			int destprefix_ofs = 0;
			int rdofs = Utils.OFS_ICMP6_DATA + 12;
			//TODO:+4_WRONG?// while (rdofs <= ntohs (v4v6plen) + 4) { ... }
			while (rdofs + 4 < pktlen) {
				if (pkt [rdofs + 1] == 0) {
					return;   /* zero length option */
				}
				if (pkt [rdofs + 0] != Utils.ND_OPT_PREFIX_INFORMATION) {
					/* skip to next option */
				} else if (pkt [rdofs + 1] != 4) {
					return;   /* bad length field */
				} else if (rdofs + (pkt [rdofs + 1] << 3) > pktlen + 4) {
					return;   /* out of packet length */
				} else if ((pkt [rdofs + 3] & (byte) 0xc0) != (byte) 0xc0) {
					/* no on-link autoconfig prefix */
				} else if (pkt [rdofs + 2] != 64) {
					return;
				} else {
					destprefix_ofs = rdofs + 16;
				}
				rdofs += (pkt [rdofs + 1] << 3);
			}
			if (destprefix_ofs > 0) {
				for (int i=0; i<8; i++) {
					local_address [0 + i] = pkt [destprefix_ofs + i];
					local_address [8 + i] = pkt [Utils.OFS_IP6_DST + 8 + i];
				}
				sharedAddress = (Inet6Address) InetAddress.getByAddress (local_address);
				//TODO// syslog (LOG_INFO, "%s: Assigning address %s to tunnel\n", program, v6prefix);
				// update_local_netconfig ();
				if (ngbcache != null) {
					ngbcache.cleanup ();
				}
				ngbcache = new NeighborCache (this, tunserver, local_address);
				maintainer.have_local_address (true);
				synchronized (maintainer) {
					maintainer.notifyAll ();
				}
				// Log.i (TAG, "Assigned address to tunnel");
			}
			return;
		//
		// Neighbor Solicitation is an attempt to reach us peer-to-peer, and should be responded to
		case Utils.ND_NEIGHBOR_SOLICIT:
			if (pktlen < 24) {
				// Too short to make sense
				return;
			}
			if (Utils.memdiff_addr (pkt, Utils.OFS_ICMP6_NGBSOL_TARGET, local_address, 0)) {
				// Neighbor Solicitation not aimed at me
				return;
			}
			if ((ngbcache == null) || !ngbcache.is6bed4 (pkt, Utils.OFS_IP6_SRC)) {
				// Source is not a 6bed4 address
				return;
			}
			//
			// Not checked here: IPv4/UDP source versus IPv6 source address (already done)
			// Not checked here: LLaddr in NgbSol -- simply send back to IPv6 src address
			//
			Utils.memcp_address (pkt, Utils.OFS_IP6_DST, pkt, Utils.OFS_IP6_SRC);
			Utils.memcp_address (pkt, Utils.OFS_IP6_SRC, local_address, 0);
			pkt [Utils.OFS_ICMP6_TYPE] = Utils.ND_NEIGHBOR_ADVERT;
			pkt [Utils.OFS_IP6_PLEN + 0] = 0;
			pkt [Utils.OFS_IP6_PLEN + 1] = 8 + 16;
			pkt [Utils.OFS_ICMP6_NGBADV_FLAGS] = 0x60;	// Solicited, Override
			// Assume that Utils.OFS_ICMP6_NGBADV_TARGET == Utils.OFS_ICMP6_NGBSOL_TARGET
			int csum = Utils.checksum_icmpv6 (pkt, 0);
			pkt [Utils.OFS_ICMP6_CSUM + 0] = (byte) (csum >> 8  );
			pkt [Utils.OFS_ICMP6_CSUM + 1] = (byte) (csum & 0xff);
			DatagramPacket replypkt = new DatagramPacket (pkt, 0, 40 + 8 + 16, src);
			super.send (replypkt);

			//
			// TODO:OLD Replicate the message over the tunnel link
			//
			// We should attach a Source Link-Layer Address, but
			// we cannot automatically trust the one provided remotely.
			// Also, we want to detect if routes differ, and handle it.
			//
			// 0. if no entry in the ngb.cache
			//    then use 6bed4 server in ND, initiate ngb.sol to src.ll
			//         impl: use 6bed4-server lladdr, set highest metric
			// 1. if metric (ngb.cache) < metric (src.ll)
			//    then retain ngb.cache, send Redirect to source
			// 2. if metric (ngb.cache) > metric (src.ll)
			//    then retain ngb.cache, initiate ngb.sol to src.ll
			// 3. if metric (ngb.cache) == metric (src.ll)
			//    then retain ngb.cache
			//
			//TODO// Handle Utils.ND_NEIGHBOR_SOLICIT (handle_4to6_nd)
			return;
		//
		// Neighbor Advertisement may be in response to our peer-to-peer search
		case Utils.ND_NEIGHBOR_ADVERT:
	//
	// Process Neighbor Advertisement coming in over 6bed4
	// First, make sure it is against an item in the ndqueue
			//
			// Validate the Neighbor Advertisement
			if (pktlen < 64) {
				// Packet too small to hold ICMPv6 Neighbor Advertisement
				return;
			}
			if ((pkt [Utils.OFS_ICMP6_TYPE] != Utils.ND_NEIGHBOR_ADVERT) || (pkt [Utils.OFS_ICMP6_CODE] != 0)) {
				// ICMPv6 Type or Code is wrong
				return;
			}
			if ((ngbcache == null) || (!ngbcache.is6bed4 (pkt, Utils.OFS_IP6_SRC)) || (!ngbcache.is6bed4 (pkt, Utils.OFS_IP6_DST))) {
				// Source or Destination IPv6 address is not a 6bed4 address
				return;
			}
			if (Utils.memdiff_addr (pkt, Utils.OFS_IP6_SRC, pkt, Utils.OFS_ICMP6_NGBADV_TARGET)) {
				// NgbAdv's Target Address does not match IPv6 source
				return;
			}
			//
			// Not checked here: IPv4/UDP source versus IPv6 source address (already done)
			//
			ngbcache.received_peer_direct_acknowledgement (pkt, Utils.OFS_ICMP6_NGBADV_TARGET, false);
			return;
		//
		// Route Redirect messages are not supported in 6bed4 draft v01
		case Utils.ND_REDIRECT:
			return;
		}
	}

    private DatagramPacket createDatagramPacket(byte pkt []) throws IOException {
		int len = Utils.fetch_net16 (pkt, Utils.OFS_IP6_PLEN) + Utils.OFS_IP6_PLOAD;
		if (len < Utils.OFS_UDP6_PLOAD) {
			throw new IOException ("Datagram packet with silly short size received over 6bed4 tunnel");
		}
		if (Utils.checksum_udpv6 (pkt, 0) != Utils.fetch_net16 (pkt, Utils.OFS_UDP6_CSUM)) {
			throw new IOException ("Datagram packet with faulty checksum received over 6bed4 tunnel");
		}
		if (Utils.fetch_net16 (pkt, Utils.OFS_UDP6_PLEN) + Utils.OFS_IP6_PLOAD > len) {
			throw new IOException ("Incomplete datagram received over 6bed4 tunnel");
		}
        DatagramPacket pkt6 = new DatagramPacket(
            Arrays.copyOfRange (pkt, Utils.OFS_UDP6_PLOAD, Utils.OFS_UDP6_PLOAD + len - 48),
            len - 48,
            (Inet6Address) InetAddress.getByAddress (Arrays.copyOfRange (pkt, Utils.OFS_IP6_SRC, Utils.OFS_IP6_SRC + 16)),
            Utils.fetch_net16 (pkt, Utils.OFS_UDP6_SRCPORT)
        );
        return pkt6;
    }

	/* Forward an IPv6 packet, wrapped into UDP and IPv4 in the 6bed4
	 * way, as a pure IPv6 packet over the tunnel interface.  This is
	 * normally a simple copying operation.  One exception exists for
	 * TCP ACK packets; these may be in response to a "playful" TCP SYN
	 * packet that was sent directly to the IPv4 recipient.  This is a
	 * piggyback ride of the opportunistic connection efforts on the
	 * 3-way handshake for TCP, without a need to modify the packets!
	 * The only thing needed to make that work is to report success
	 * back to the Neighbor Cache, in cases when TCP ACK comes back in
	 * directly from the remote peer.
	 *
	 * Note that nothing is stopping an ACK packet that is meaningful
	 * to us from also being a SYN packet that is meaningful to the
	 * remote peer.  We will simply do our thing and forward any ACK
	 * to the most direct route we can imagine -- which may well be
	 * the sender, _especially_ since we opened our 6bed4 port to the
	 * remote peer when sending our playful initial TCP packet.
	 *
	 * Observing the traffic on the network, this may well look like
	 * magic!  All you see is plain TCP traffic crossing over directly
	 * if it is possible --and bouncing one or two packets through the
	 * tunnel otherwise-- and especially in the case where it can work
	 * directly it will be a surprise.  Servers are therefore strongly
	 * encouraged to setup port forwarding for their 6bed4 addresses,
	 * or just open a hole in full cone NAT/firewall setups.  This will
	 * mean zero delay and zero bypasses for 6bed4 on the majority of
	 * TCP connection initiations between 6bed4 peers!
	 */
	public void handle_4to6_plain (byte pkt [], int pktlen)
	throws IOException {
		//
		// Check if the designated queue for this packet exists
		int port = Utils.fetch_net16 (pkt, Utils.OFS_UDP6_DSTPORT);
		//TODO// Handling for udp_clients: only for UDP-over-IPv6, only to the default address
		BlockingQueue<DatagramPacket> udp_client = udp_clients [port];
		if (udp_client == null) {
			return;
		}
		// The buffer is already full -- drop the oldest element
		if (udp_client.remainingCapacity () == 0) {
			/* (void) */ udp_client.poll ();
		}
		//
		// If this is a successful peering attempt, that is, a tcpack packet, report that back
		// Note that the UDP/IPv4 source has already been validated against the IPv6 source
		boolean tcpack = (pktlen >= 40 + 20) && (pkt [Utils.OFS_IP6_NXTHDR] == Utils.IPPROTO_TCP) && ((pkt [Utils.OFS_TCP6_FLAGS] & Utils.TCP_FLAG_ACK) != 0x00);
		if (tcpack) {
			if ((ngbcache != null) && ngbcache.is6bed4 (pkt, Utils.OFS_IP6_SRC)) {
				ngbcache.received_peer_direct_acknowledgement (pkt, Utils.OFS_IP6_SRC, true);
			}
		}
		//
		// Enqueue the packet in the designated client queue
		//TODO// Select whether this is UDP/TCP/??? for the shared address, or raw for unique addresses!
		udp_client.offer (createDatagramPacket(pkt));
	}

	/** Handle a 6bed4 packet that is being stripped and passed on as
	 * an IPv6 packet.  Returns true if the packet is suitable to be
	 * relayed as IPv6.
	 */
	public void handle_4to6 (DatagramPacket datagram)
	throws IOException {
		byte pkt [] = datagram.getData ();
		int pktlen = datagram.getLength ();

		if (pktlen < 40) {
			return;
		}
		if ((pkt [0] & (byte) 0xf0) != 0x60) {
			return;
		}
		validate_originator (pkt, (InetSocketAddress) datagram.getSocketAddress ());
		if ((pkt [Utils.OFS_IP6_NXTHDR] == Utils.IPPROTO_ICMPV6) && (pkt [Utils.OFS_ICMP6_TYPE] >= Utils.ND_LOWEST) && (pkt [Utils.OFS_ICMP6_TYPE] <= Utils.ND_HIGHEST)) {
			//
			// Not Plain: Router Adv/Sol, Neighbor Adv/Sol, Redirect
			handle_4to6_nd (pkt, pktlen, datagram.getSocketAddress ());
			return;
		} else {
			//
			// Plain Unicast or Plain Multicast (both may enter)
			handle_4to6_plain (pkt, pktlen);
			return;
		}
	}

	public void validate_originator (byte pkt [], InetSocketAddress originator)
	throws IOException {
/* TODO: validate originator address
		if (tunserver.equals (originator)) {
			return;
		}
		if (memdiff_halfaddr (pkt, Utils.OFS_IP6_SRC, router_linklocal, 0) && ((local_address == null) || memdiff_halfaddr (pkt, Utils.OFS_IP6_SRC, local_address, 8))) {
			throw new IOException ("Incoming 6bed4 uses bad /64 prefix");
		}
		int port = (pkt [Utils.OFS_IP6_SRC + 8] ^ 0x02) & 0xff;
		port = (port | (pkt [Utils.OFS_IP6_SRC + 9] << 8) & 0xffff;
		if (originator.getPort () != port) {
			throw new IOException ("Incoming 6bed4 uses ")
		}
*/
	}

	/* This routine passes IPv6 traffic from the tunnel interface on
	 * to the 6bed4 interface where it is wrapped into UDP and IPv4.
	 * The only concern for this is where to send it to -- should it
	 * be sent to the tunnel server, or directly to the peer?  The
	 * Neighbor Cache is consulted for advise.
	 *
	 * A special flag exists to modify the behaviour of the response
	 * to this inquiry.  This flag is used to signal that a first
	 * packet might be tried directly, which should be harmless if
	 * it fails and otherwise lead to optimistic connections if:
	 *  1. the packet will repeat upon failure, and
	 *  2. explicit acknowledgement can be reported to the cache
	 * This is the case with TCP connection setup; during a SYN,
	 * it is possible to be playful and try to send the first
	 * packet directly.  A TCP ACK that returns directly from the
	 * sender indicates that return traffic is possible, which is
	 * then used to update the Neighbor Cache with positivism on
	 * the return route.
	 */
	public void handle_6to4_plain_unicast (byte pkt [], int pktlen)
	throws IOException {
		InetSocketAddress target;
		if ((ngbcache != null) && ngbcache.is6bed4 (pkt, 24)) {
			boolean tcpsyn = (pkt [Utils.OFS_IP6_NXTHDR] == Utils.IPPROTO_TCP) && ((pkt [Utils.OFS_TCP6_FLAGS] & Utils.TCP_FLAG_SYN) != 0x00);
			target = ngbcache.lookup_neighbor (pkt, 24, tcpsyn);
		} else {
			target = tunserver;
		}
	}

	public void handle_6to4_nd (byte pkt [], int pktlen)
	throws IOException {
		throw new RuntimeException ("You should not be trying to send ND over the 6bed4 interface");
/* TODO: Entire routine can probably be removed
		switch (pkt [Utils.OFS_ICMP6_TYPE]) {
		//
		// Handle Router Solicitation by answering it with the local configuration
		case Utils.ND_ROUTER_SOLICIT:
			int ofs = Utils.OFS_ICMP6_TYPE;
			pkt [ofs++] = Utils.ND_ROUTER_ADVERT;		// type
			pkt [ofs++] = 0;					// code
			ofs += 2;							// checksum
			pkt [ofs++] = 0;					// hop limit -- unspecified
			pkt [ofs++] = 0x18;					// M=0, O=0, H=0, Prf=11=Low, Reserved=0
			pkt [ofs++] = 0x00;					// Lifetime
			pkt [ofs++] = 0x00;					// (cont)
			for (int i=0; i<8; i++) {
				pkt [ofs++] = 0;				// Reachable time, Retrans timer
			}
			pkt [ofs-6] = (byte) 0x80;			// Reachable time := 32s
			pkt [ofs-2] = 0x01;					// Retrans timer := 0.25s
			// Start of Prefix Option
			pkt [ofs++] = Utils.ND_OPT_PREFIX_INFORMATION;
			pkt [ofs++] = 4;		// Option length = 4 * 8 bytes
			pkt [ofs++] = (byte) 128;		// Announce a /64 prefix (TODO: Temporarily /128)
			pkt [ofs++] = (byte) 0x80;	// Link-local, No autoconfig, tunnel does the work
			for (int i=0; i<8; i++) {
				pkt [ofs++] = (byte) 0xff;		// Valid / Preferred Lifetime: Infinite
			}
			for (int i=0; i<4; i++) {
				pkt [ofs++] = 0;				// Reserved
			}
			Utils.memcp_address (pkt, ofs, local_address, 0);
			ofs += 16;
			// End of Prefix Option
			Utils.memcp_address (pkt, Utils.OFS_IP6_DST, pkt, Utils.OFS_IP6_SRC);	// dst:=src
			Utils.memcp_address (pkt, Utils.OFS_IP6_SRC, local_address, 0);
			//TODO// Send packet back to IPv6 downlink
			return;
		//
		// Handle Router Advertisement by dropping it -- Android is not setup a router
		case Utils.ND_ROUTER_ADVERT:
			return;
		//
		// Neighbor Solicitation is not normally sent by the phone due to its /128 on 6bed4
		case Utils.ND_NEIGHBOR_SOLICIT:
			return;
		//
		// Neighbor Advertisement is a response to a peer, and should be relayed
		case Utils.ND_NEIGHBOR_ADVERT:
			//TODO// Possibly arrange the peer's receiving address
			handle_6to4_plain_unicast (pkt, pktlen);
			return;
		// Route Redirect messages are not supported in 6bed4 draft v01
		case Utils.ND_REDIRECT:
			return;
		}
*/
	}

	public void handle_6to4 (byte pkt [], int pktlen)
	throws IOException {
		if (pktlen < 41) {
			return;
		}
		if ((pkt [0] & 0xf0) != 0x60) {
			return;
		}
		if ((pkt [Utils.OFS_IP6_NXTHDR] == Utils.IPPROTO_ICMPV6) && (pkt [Utils.OFS_ICMP6_TYPE] >= Utils.ND_LOWEST) && (pkt [Utils.OFS_ICMP6_TYPE] <= Utils.ND_HIGHEST)) {
			//
			// Not Plain: Router Adv/Sol, Neighbor Adv/Sol, Redirect
			handle_6to4_nd (pkt, pktlen);
		} else if ((pkt [Utils.OFS_IP6_DST+0] != 0xff) && ((pkt [Utils.OFS_IP6_DST+8] & 0x01) == 0x00)) {
			//
			// Plain Unicast
			pkt [Utils.OFS_IP6_HOPS]--;
			if (pkt [Utils.OFS_IP6_HOPS] == 0) {
				return;
			}
			handle_6to4_plain_unicast (pkt, pktlen);
		} else {
			//
			// Plain Multicast
			//TODO: Ignore Multicast for now...
		}
	}


	/** The Worker inner class ensures that incoming traffic, and that
	 * includes 6bed4 tunnel management traffic, is processed as soon
	 * as it arrives.  This means that applications need not actively
	 * read input to get it processed.  Furthermore, this approach
	 * simplifies receiving all 6bed4 traffic on one IPv4/UDP socket
	 * and subsequently dispatching it to the various 6bed4 sockets
	 * connected to the same ServerNode, and possibly each applying
	 * their own idea of a socket timeout or other queueing disciplines.
	 * The expense (there always seems to be one) is having to queue
	 * received data between the ServerNode and the 6bed4 socket.
	 */
	private class Worker extends Thread {

		protected ServerNode uplink;

		/** The thread logic for the Worker inner class comes down
		 * to reading input from the IPv4/UDP socket, seeing if it
		 * needs local handling as a 6bed4 management packet, and
		 * otherwise shipping it off to the queue of a 6bed4 socket
		 * that is read when the user of the DatagramSocket6bed4
		 * wants to grab its input.  Note how this reflects the way
		 * that native UDP ports operate -- packets wait until they
		 * are picked up.
		 */
		public void run () {
			DatagramPacket dgram4 = null;
			while (!isInterrupted ()) {
				try {
					dgram4 = new DatagramPacket (new byte [1280 + 28], 1280 + 28);
					uplink.receive (dgram4);
					handle_4to6 (dgram4);
				} catch (IOException ioe) {
					; //TODO// What to do here?  Not sure...
				}
			}
		}

		public Worker (ServerNode owner) {
			this.uplink = owner;
			setDaemon (true);
		}

	}

	/** The Maintainer inner class performs regular maintainence.
	 * One task is to acquire the router address by sending regular
	 * Router Solicitation messages to the 6bed4 tunnel server,
	 * and once it has an address it will regularly send keep-alives.
	 */
	private class Maintainer extends Thread {

		/* The time for the next scheduled maintenance: routersol or keepalive.
		 * The milliseconds are always 0 for maintenance tasks.
		 */
		private long maintenance_time_millis;
		private int maintenance_time_cycle = 0;
		private int maintenance_time_cycle_max = 30;
		private boolean have_lladdr = false;
		private DatagramPacket keepalive_packet = null;
		private DatagramSocket uplink;

		/* Perform the initial Router Solicitation exchange with the public server.
		 */
		public void solicit_router () {
			if (uplink != null) {
				try {
					DatagramPacket rtrsol = new DatagramPacket (Utils.router_solicitation, Utils.router_solicitation.length, tunserver);
					uplink.send (rtrsol);
				} catch (IOException ioe) {
					/* Network is probably down, so don't
					 * throw new RuntimeException ("Network failure", ioe);
					 */
				}
			}
		}

		/* Send a KeepAlive packet to the public server.
		 * Note, ideally, we would set a low-enough TTL to never reach it;
		 * after all, the only goal is to open /local/ firewalls and NAT.
		 * Java however, is not capable of setting TTL on unicast sockets.
		 */
		public void keepalive () {
			if ((keepalive_packet != null) && (uplink != null)) {
				try {
					uplink.send (keepalive_packet);
					// Log.i (TAG, "Sent KeepAlive (empty UDP) to Tunnel Server");
				} catch (IOException ioe) {
					;	/* Network is probably down; order reconnect to tunnel server */
					have_lladdr = false;
				}
			}
		}

		/* Perform regular maintenance tasks: KeepAlive, and requesting a local address.
		 */
		public void regular_maintenance () {
			if (!have_lladdr) {
				solicit_router ();
				maintenance_time_cycle <<= 1;
				maintenance_time_cycle += 1;
				if (maintenance_time_cycle > maintenance_time_cycle_max) {
					maintenance_time_cycle = maintenance_time_cycle_max;
				}
				//TODO// syslog (LOG_INFO, "Sent Router Advertisement to Public 6bed4 Service, next attempt in %d seconds\n", maintenance_time_cycle);
				// Log.i (TAG, "Sent Router Advertisement to Tunnel Server");
			} else {
				//TODO// syslog (LOG_INFO, "Sending a KeepAlive message (empty UDP) to the 6bed4 Router\n");
				keepalive ();
				if (have_lladdr) {
					maintenance_time_cycle = maintenance_time_cycle_max;
				} else {
					maintenance_time_cycle = 1;
				}
			}
			maintenance_time_millis = System.currentTimeMillis () + 1000 * (long) maintenance_time_cycle;
		}

		/* Run the regular maintenance thread.  This involves sending KeepAlives
		 * and possibly requesting a local address through Router Solicitation.
		 */
		public void run () {
			try {
				while (!isInterrupted ()) {
					regular_maintenance ();
					sleep (maintenance_time_millis - System.currentTimeMillis());
				}
			} catch (InterruptedException ie) {
				return;
			}
		}

		/* Tell the maintenance routine whether a local address has been setup.
		 * Until this is called, the maintenance will focus on getting one through
		 * regular Router Solicitation messages.  It is possible to revert to this
		 * behaviour by setting the flag to false; this can be useful in case of
		 * changes, for instance resulting from an IPv4 address change.
		 */
		public void have_local_address (boolean new_setting) {
			have_lladdr = new_setting;
			if (have_lladdr) {
				maintenance_time_cycle = maintenance_time_cycle_max;
				maintenance_time_millis = System.currentTimeMillis () + 1000 * maintenance_time_cycle;
			}
		}

		/* See if a local address has been setup.
		 */
		public boolean have_local_address () {
			return have_lladdr;
		}

		/* Construct the Maintainer thread.
		 */
		public Maintainer (DatagramSocket uplink) {
			this.uplink = uplink;
            byte payload[] = { };
            keepalive_packet = new DatagramPacket (payload, 0, tunserver);
			setDaemon (true);
		}
	}


}

