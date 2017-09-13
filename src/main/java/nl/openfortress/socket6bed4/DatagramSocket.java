package nl.openfortress.socket6bed4;


import java.net.DatagramPacket;
import java.net.DatagramSocketImpl;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.io.IOException;

import java.util.Arrays;
import java.nio.ByteBuffer;


/** Socket6bed4 describes sockets that are run over IPv6.  This means
 * that a remote IPv6 address can be contacted when there are only
 * IPv4 addresses available locally.
 *
 * A Socket6bed4 can switch between IPv4 transports; it can either send
 * to a 6bed4 server, or directly to the targeted peer.  Either path is
 * acceptable as.  The Socket can arrange this automatically, using
 * peering attempts through Neighbor Discovery.
 *
 * Perhaps it's a bit silly to make a 6bed4 DatagramSocket a subclass
 * of a plain DatagramSocket.  It is very practical however; it means
 * that these objects can be substituted anywhere, without question.
 */
public class DatagramSocket extends java.net.DatagramSocket {

	protected static java.net.DatagramSocket server_ipv4socket;
	protected java.net.DatagramSocket ipv4socket;
	protected InetSocketAddress cnx6sa = null;
	protected InetSocketAddress my6sa = null;
	protected ServerNode my6sn = null;
	protected int ephemeral = 3210;
	static final byte prephdr_payload [] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, Utils.IPPROTO_UDP, 64 /*HopLimit*/ };
	protected byte prephdr_udp [] = new byte [8];

	/* Tell this connection to switch back to the default server,
	 * skipping any direct route.
	 */
	public void useDefaultServer () {
		ipv4socket = server_ipv4socket;
	}

	/* Set the IPv4 address and UDP port of the default server,
	 * as shared by all sockets.  Note that sockets will not
	 * move over immediately.  Invoke useDefaultServer() if this
	 * is needed.
	 */
	public void setDefaultServer (Inet4Address server4, int port4)
	throws SocketException {
		DatagramSocket sox = new DatagramSocket ();
		sox.connect (server4, port4);
		server_ipv4socket = sox;
	}


    /* @return current remote address */
    @Override
	public InetAddress getInetAddress () {
		return (cnx6sa != null)? cnx6sa.getAddress (): null;
	}

	/** @return current local port */
    @Override
	public int getPort () {
		return (cnx6sa != null)? cnx6sa.getPort (): 0;
	}

	/** @return remote sock address */
    @Override
	public InetSocketAddress getRemoteSocketAddress () {
		return cnx6sa;
	}

	/** @return local address */
    @Override
	public InetAddress getLocalAddress () {
		return my6sa.getAddress ();
	}

	/** @return local port */
    @Override
	public int getLocalPort () {
		return my6sa.getPort ();
	}

	/** @return bound local socket address */
    @Override
	public InetSocketAddress getLocalSocketAddress () {
		return my6sa;
	}

	public void bind (int port)
	throws SocketException {
		//
		// Verify if binding request is properly formed
		if (port == 0) {
			// Although I did not see it specified, this C-ism is apparently used a lot
			bind ((InetSocketAddress) null);
			return;
		}
		if ((port <= 0) || (port > 65535)) {
			throw new SocketException ("Binding is only possible to ports from 1 to 65535");
		}
		//TODO// Checks against Router Advertisement
		//
		// Perform the actual binding, and unbind old
		ConnectionPool pool = ConnectionPool.getSharedConnectionPool ();
		my6sn = pool.getDefaultServerNode ();
		synchronized (this) {
			my6sn.registerDatagramClient (port);
			if (my6sa != null) {
				my6sn.unregisterDatagramClient (my6sa.getPort ());
			}
			prephdr_udp [0] = (byte) (port >> 8);
			prephdr_udp [1] = (byte) (port & 0x00ff);
			my6sa = new InetSocketAddress (my6sn.getShared6bed4Address (), port);
		}
	}

	/** Attempt to bind to an address and/or port, exercising
	 * 6bed4 constraints as they arise from the router advertisement.
     * @param sa
     * @throws java.net.SocketException
	 */
	public void bind (InetSocketAddress sa)
	throws SocketException {
		if (sa == null) {
			//
			// Iterate over ports until one is found to be free
			for (int i=0; i < 4095; i++) {
				ephemeral = (ephemeral + 1) & 0x0ffff;
				try {
					bind (ephemeral + 49152);
					return;	/* No complaints? Than break out of the loop */
				} catch (SocketException se) {
					/* Taken?  Then continue trying */
				}
			}
			throw new SocketException ("No ephemeral ports are free on the 6bed4 address");

		} else {
			bind (sa.getPort ());
		}
	}

	/** Are we bound?
     * @return  */
    @Override
	public boolean isBound () {
		return my6sa != null;
	}

	/** Connect to a remote IPv6 address and UDP port. */
    @Override
	public void connect (InetAddress address, int port) {
		connect (new InetSocketAddress (address, port));
	}
	public void connect (InetSocketAddress addr) {
		cnx6sa = (InetSocketAddress) addr;
		prephdr_udp [2] = (byte) (cnx6sa.getPort () >> 8);
    	prephdr_udp [3] = (byte) (cnx6sa.getPort () & 0x00ff);

	}

	/** Disconnect from a remote IPv6 address and UDP port. */
    @Override
	public void disconnect () {
		cnx6sa = null;
	}

	/** Are we connected? */
    @Override
	public boolean isConnected () {
		return cnx6sa != null;
	}


	/** The interface for DatagramPackets conceals the UDP layer
	 * underlying the actual data exchanged.  For 6bed4 however,
	 * a few headers will have to be prefixed.  These are the
	 * IPv6 header and UDP-over-IPv6 header.  The underlying
	 * DatagramSocket for IPv4 will conceal the UDP-over-IPv4.
	 *
	 * Details about playful hints are described in the class
	 * NeighborCache.  In general, the hint should only be given
	 * for packets that will be re-sent upon failure, and whose
	 * success of delivery can be reported back.  This can then
	 * be used to setup direct connections to peers without
	 * explicit negotiation through Neighbor Discovery.  You can
	 * safely set the playful flag on all similar traffic, as it
	 * will only influence on initial attempts at traffic.  A good
	 * efficiency trade-off is to use playful hints only on
	 * initiating UDP messages, such as a SIP INVITE.
     * @param pkt6
     * @param playful
     * @throws java.io.IOException
	 */
	public void send_playful (DatagramPacket pkt6, boolean playful)
	throws IOException {
		int pkt6len = pkt6.getLength ();
		ByteBuffer buf = ByteBuffer.allocate (Utils.OFS_UDP6_PLOAD + pkt6len);
		buf.put (prephdr_payload);
		buf.put ( my6sa.getAddress ().getAddress ());
		Inet6Address remote;
		if (cnx6sa != null) {
			remote = (Inet6Address) cnx6sa.getAddress ();
		} else {
			remote = (Inet6Address) pkt6.getAddress ();
		}
		buf.put (remote.getAddress ());
		buf.put (prephdr_udp);
		buf.put (pkt6.getData (), pkt6.getOffset (), pkt6len);
		byte[] tundata = buf.array ();
		tundata [Utils.OFS_IP6_PLEN + 0] =
		tundata [Utils.OFS_UDP6_PLEN + 0] = (byte) ((pkt6len + 8) >> 8);
		tundata [Utils.OFS_IP6_PLEN + 1] =
		tundata [Utils.OFS_UDP6_PLEN + 1] = (byte) ((pkt6len + 8) & 0x00ff);
		if (cnx6sa == null) {
			int rport = pkt6.getPort ();
			tundata [Utils.OFS_UDP6_DSTPORT + 0] = (byte) (rport >> 8);
			tundata [Utils.OFS_UDP6_DSTPORT + 1] = (byte) (rport & 0x00ff);
		}
		int csum = Utils.checksum_udpv6 (tundata);
		tundata [Utils.OFS_UDP6_CSUM + 0] = (byte) (csum >> 8);
		tundata [Utils.OFS_UDP6_CSUM + 1] = (byte) (csum & 0x00ff);
		//TODO// Shared and locked send4 instead of local pkt4
		DatagramPacket pkt4 = new DatagramPacket (tundata, 0, tundata.length);
		pkt4.setSocketAddress (my6sn.lookup_neighbor ((Inet6Address) pkt6.getAddress (), playful));
		my6sn.send (pkt4);
	}


	/** Receive a packet from the underlying IPv4 layer.  As with
	 * sending, the UDP underneath the packet is hidden, but for
	 * 6bed4 the IPv6 and UDP-over-IPv6 headers must be stripped
	 * and interpreted.  Only traffic destined for our own
	 * combination of IPv6 address and UDP-over-IPv6 port will be
	 * passed on to us.
	 *
	 * The hint returned indicates if the datagram was received
	 * directly from the peer.  This information may be of varying
	 * use to implementations, but it would be specifically useful
	 * for confirmation of playfully sent packets, as described
	 * for the send_playful () method.  To this end, the method
	 * acknowledge_playful () is used to complete the cycle of
	 * optimistic direct connections to peers.
     * @param pkt6
     * @return
     * @throws java.io.IOException
	 */
	public boolean receive_playful (DatagramPacket pkt6)
	throws IOException {
		byte msg[] = my6sn.receive_datagram (my6sa.getPort (), getSoTimeout ());
		if (msg == null) {
			throw new SocketTimeoutException ("No data available within timeout");
		}
		int len = Utils.fetch_net16 (msg, Utils.OFS_IP6_PLEN) + Utils.OFS_IP6_PLOAD;
		if (len < Utils.OFS_UDP6_PLOAD) {
			throw new IOException ("Datagram packet with silly short size received over 6bed4 tunnel");
		}
		if (Utils.checksum_udpv6 (msg, 0) != Utils.fetch_net16 (msg, Utils.OFS_UDP6_CSUM)) {
			throw new IOException ("Datagram packet with faulty checksum received over 6bed4 tunnel");
		}
		if (Utils.fetch_net16 (msg, Utils.OFS_UDP6_PLEN) + Utils.OFS_IP6_PLOAD > len) {
			throw new IOException ("Incomplete datagram received over 6bed4 tunnel");
		}
		pkt6.setAddress ((Inet6Address) InetAddress.getByAddress (Arrays.copyOfRange (msg, Utils.OFS_IP6_SRC, Utils.OFS_IP6_SRC + 16)));
		pkt6.setPort (Utils.fetch_net16 (msg, Utils.OFS_UDP6_SRCPORT));
		// PROBABLY FORMALLY CORRECT, BUT NOT HOW PEOPLE USE IT: pkt6.setData (msg, Utils.OFS_UDP6_PLOAD, len);
		pkt6.setData (Arrays.copyOfRange (msg, Utils.OFS_UDP6_PLOAD, Utils.OFS_UDP6_PLOAD + len - 48), 0, len - 48);
		//TODO// return ! pkt4.getAddress ().equals (ipv4socket.getInetAddress ());
		return false;
	}

	/** In a playfully hinting exchange with send_playful() and
	 * receive_playful(), this is the final acknowledgement that
	 * should be called upon completion.  This acknowledges a
	 * reliable direct connection to a peer without a need to
	 * go through explicit Neighbor Discovery.  The pkt6
	 * parameter holds the remote peer's address.
	 *
	 * Note that invoking this function when receive_playful()
	 * returned false for the exchane is a damn lie, and may
	 * end up configuring the NeighborCache entry for this
	 * neighbor with a direct route that does not actually
	 * function.  You will then end up sending messages into
	 * oblivia.
	 *
	 * Also note that plaful sends are an optimistic variation
	 * that is not strictly necessary; the NeighborCache has
	 * its own method builtin, based on Neighbor Discovery.
	 * If a direct link to a peer is possible at all, then
	 * this will find it.  Only if you wish to use the
	 * optimistic variation to avoid these extra exchanges
	 * should you consider playful mode.  After all this
	 * discouraging information it should also be noted that
	 * your network traffic will look extremely cool if it
	 * manages to get through directly to a 6bed4 peer without
	 * any explicit negotiation!
     * @param ia6bed4
	 */
	public void acknowledge_playful (Inet6Address ia6bed4) {
		my6sn.acknowledge_playful (ia6bed4.getAddress(), 0);
	}

	/** The "standard" interface for sending bytes, overriding the
	 * parent function and not sending playful hints.
     * @param pkt6
     * @throws java.io.IOException
	 */
    @Override
	public void send (DatagramPacket pkt6)
	throws IOException {
		send_playful (pkt6, false);
	}

	/** The "standard" interface for receiving bytes, overriding the
	 * parent function and not supporting playful operation.
     * @param pkt6
     * @throws java.io.IOException
	 */
    @Override
	public void receive (DatagramPacket pkt6)
	throws IOException {
		/*(void)*/ receive_playful (pkt6);
	}


	/** Construct a new DatagramSocket6bed4 based on an underlying
	 * DatagramSocket for IPv4.
     * @param bindaddr
     * @throws java.net.SocketException
	 */
	public DatagramSocket (InetSocketAddress bindaddr)
	throws SocketException {
		super ();
		bind (bindaddr);
	}
	public DatagramSocket (int port, Inet6Address bindaddr)
	throws SocketException  {
		this (new InetSocketAddress (bindaddr, port));
	}
	public DatagramSocket (int port)
	throws SocketException  {
		this (port, null /*TODO:INADDR_ANY*/);
	}
	public DatagramSocket ()
	throws SocketException  {
		super ();
		bind ((InetSocketAddress) null);
	}
	public DatagramSocket (DatagramSocketImpl impl)
	throws SocketException  {
		throw new RuntimeException ("Cannot choose DatagramSocketImpl");
	}


}

