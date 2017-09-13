package nl.openfortress.socket6bed4;


import java.net.Inet6Address;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.InetAddress;
import java.net.SocketAddress;



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

    protected DatagramSocket(DatagramSocketImpl impl) {
        super(impl);
        impl.setDatagramSocket(this);
    }
	/** Construct a new DatagramSocket6bed4 based on an underlying
	 * DatagramSocket for IPv4.
     * @param bindaddr
     * @throws java.net.SocketException
	 */
	public DatagramSocket (SocketAddress bindaddr)
	throws SocketException {
		this(new DatagramSocketImpl());
        if (bindaddr != null) {
            try {
                bind(bindaddr);
            } finally {
                if (!isBound())
                    close();
            }
        }
	}

	public DatagramSocket (int port, InetAddress bindaddr)
	throws SocketException  {
		this(new InetSocketAddress(bindaddr, port));
	}
	public DatagramSocket (int port)
	throws SocketException  {
		this(port, null);
	}
	public DatagramSocket ()
	throws SocketException  {
		this(new InetSocketAddress(0));
	}
}

