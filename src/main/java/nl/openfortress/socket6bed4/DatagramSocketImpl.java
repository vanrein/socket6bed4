/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.openfortress.socket6bed4;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.concurrent.ConcurrentLinkedQueue;
/**
 *
 * @author hfman
 */
public class DatagramSocketImpl extends java.net.DatagramSocketImpl{
	static final byte prephdr_payload [] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, Utils.IPPROTO_UDP, 64 /*HopLimit*/ };
    protected int ephemeral = 3210;
    private java.net.DatagramSocket standardSocket;
    private Thread standardThread;
    private ConcurrentLinkedQueue<Thread> blockingThreads;
    /**
     * The DatagramSocket or MulticastSocket
     * that owns this impl
     */
    DatagramSocket socket;

    void setDatagramSocket(DatagramSocket socket) {
        this.socket = socket;
    }

    @Override
    protected void create() throws SocketException {
        blockingThreads = new ConcurrentLinkedQueue<Thread>();
    }

    private void createStandardSocket() {
        try {
            standardSocket = new java.net.DatagramSocket(socket.getLocalPort());
            System.err.println(standardSocket.getLocalSocketAddress());
        } catch (SocketException ex) {
            Logger.getLogger(DatagramSocketImpl.class.getName()).log(Level.SEVERE, "Could not create standard socket", ex);
        }
    }

    private void bind(int lport)  throws SocketException {
		//TODO// Checks against Router Advertisement
		//
		// Perform the actual binding, and unbind old
		ConnectionPool pool = ConnectionPool.getSharedConnectionPool ();
		socket.my6sn = pool.getDefaultServerNode ();
		synchronized (this) {
			socket.my6sn.registerDatagramClient (lport);
			if (socket.my6sa != null) {
				socket.my6sn.unregisterDatagramClient (socket.my6sa.getPort ());
			}
			socket.prephdr_udp [0] = (byte) (lport >> 8);
			socket.prephdr_udp [1] = (byte) (lport & 0x00ff);
			socket.my6sa = new InetSocketAddress (socket.my6sn.getShared6bed4Address (), lport);
		}
    }

    private void findFreeLocalPort()  throws SocketException {
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
    }

    @Override
    protected void bind(int lport, InetAddress laddr) throws SocketException {
		if (lport == 0) {
            findFreeLocalPort();
		} else {
            bind(lport);
        }
        final int boundPort = socket.getLocalPort();
        createStandardSocket();
        standardThread = new Thread() {
            @Override
            public void run() {
                System.err.println("Standard thread starting: " + Thread.currentThread().getName());
                try {
                    for (;;) {
                        DatagramPacket dgram4 = new DatagramPacket (new byte [1280 + 28], 1280 + 28);
                        standardSocket.receive(dgram4);
                        System.err.println("Standard thread received packet: " + new String(dgram4.getData(), 0, dgram4.getLength()));
                        socket.my6sn.udp_clients[boundPort].offer(dgram4);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(DatagramSocketImpl.class.getName()).log(Level.SEVERE, null, ex);
                }
                System.err.println("Standard thread exiting");
            }
        };
        standardThread.start();

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
	private void send_playful (DatagramPacket pkt6, boolean playful)
	throws IOException {
		int pkt6len = pkt6.getLength ();
		ByteBuffer buf = ByteBuffer.allocate (Utils.OFS_UDP6_PLOAD + pkt6len);
		buf.put (prephdr_payload);
		buf.put ( socket.my6sa.getAddress ().getAddress ());
		Inet6Address remote;
		if (socket.cnx6sa != null) {
			remote = (Inet6Address) socket.cnx6sa.getAddress ();
		} else {
			remote = (Inet6Address) pkt6.getAddress ();
		}
		buf.put (remote.getAddress ());
		buf.put (socket.prephdr_udp);
		buf.put (pkt6.getData (), pkt6.getOffset (), pkt6len);
		byte[] tundata = buf.array ();
		tundata [Utils.OFS_IP6_PLEN + 0] =
		tundata [Utils.OFS_UDP6_PLEN + 0] = (byte) ((pkt6len + 8) >> 8);
		tundata [Utils.OFS_IP6_PLEN + 1] =
		tundata [Utils.OFS_UDP6_PLEN + 1] = (byte) ((pkt6len + 8) & 0x00ff);
		if (socket.cnx6sa == null) {
			int rport = pkt6.getPort ();
			tundata [Utils.OFS_UDP6_DSTPORT + 0] = (byte) (rport >> 8);
			tundata [Utils.OFS_UDP6_DSTPORT + 1] = (byte) (rport & 0x00ff);
		}
		int csum = Utils.checksum_udpv6 (tundata);
		tundata [Utils.OFS_UDP6_CSUM + 0] = (byte) (csum >> 8);
		tundata [Utils.OFS_UDP6_CSUM + 1] = (byte) (csum & 0x00ff);
		//TODO// Shared and locked send4 instead of local pkt4
		DatagramPacket pkt4 = new DatagramPacket (tundata, 0, tundata.length);
		pkt4.setSocketAddress (socket.my6sn.lookup_neighbor ((Inet6Address) pkt6.getAddress (), playful));
		socket.my6sn.send (pkt4);
	}

	/** The "standard" interface for sending bytes, overriding the
	 * parent function and not sending playful hints.
     * @param p
     * @throws java.io.IOException
	 */
    @Override
    protected void send(DatagramPacket p) throws IOException {
        if (p.getAddress() instanceof Inet4Address) {
            standardSocket.send(p);
        } else {
            send_playful(p, false);
        }
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
		DatagramPacket msg = socket.my6sn.receive_datagram (socket.my6sa.getPort (), socket.getSoTimeout ());
		if (msg == null) {
			throw new SocketTimeoutException ("No data available within timeout");
		}
		pkt6.setAddress (msg.getAddress());
		pkt6.setPort (msg.getPort());
		pkt6.setData (msg.getData());
		return false;
	}

    private void joinStandardThread() {
        if (standardThread == null) {
            System.err.println("Standard thread not active");
        } else {
            System.err.println("Joining standard thread");
            try {
                standardThread.join();
                System.err.println("Standard thread joined");
            } catch (InterruptedException ex) {
                Logger.getLogger(DatagramSocketImpl.class.getName()).log(Level.SEVERE, null, ex);
            }
            standardThread = null;
        }
    }
	/** The "standard" interface for receiving bytes, overriding the
	 * parent function and not supporting playful operation.
     * @param pkt6
     * @throws java.io.IOException
	 */
    @Override
    protected void receive(DatagramPacket pkt6) throws IOException {
        final Thread thread6bed4 = Thread.currentThread();

        blockingThreads.add(thread6bed4);
        /*(void)*/ receive_playful (pkt6);
        blockingThreads.remove(thread6bed4);
    }


    @Override
    protected int peek(InetAddress i) throws IOException {
        throw new UnsupportedOperationException("Not supported yet4."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected int peekData(DatagramPacket p) throws IOException {
        throw new UnsupportedOperationException("Not supported yet5."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void setTTL(byte ttl) throws IOException {
        throw new UnsupportedOperationException("Not supported yet7."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected byte getTTL() throws IOException {
        throw new UnsupportedOperationException("Not supported yet8."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void setTimeToLive(int ttl) throws IOException {
        throw new UnsupportedOperationException("Not supported yet9."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected int getTimeToLive() throws IOException {
        throw new UnsupportedOperationException("Not supported yet10."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void join(InetAddress inetaddr) throws IOException {
        throw new UnsupportedOperationException("Not supported yet11."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void leave(InetAddress inetaddr) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void joinGroup(SocketAddress mcastaddr, NetworkInterface netIf) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void leaveGroup(SocketAddress mcastaddr, NetworkInterface netIf) throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected void close() {
        System.err.println("CLOSE()");
        for (Thread t : blockingThreads) {
            t.interrupt();
        }
        try {
            socket.my6sn.unregisterDatagramClient (socket.my6sa.getPort ());
        } catch (SocketException ex) {
            Logger.getLogger(DatagramSocketImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (standardSocket != null) {
            standardSocket.close();
            standardSocket = null;
            joinStandardThread();
        }
    }

    public void setOption(int optID, Object value) throws SocketException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public Object getOption(int optID) throws SocketException {
        return null;
    }

}
