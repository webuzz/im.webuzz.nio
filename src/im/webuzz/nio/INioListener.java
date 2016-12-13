package im.webuzz.nio;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public interface INioListener {

	public void sslHandshakeFinished();
	public void sslHandshakeTimeout();
	public void connectionFailed(NioConnector sessionMetadata);
	public void connectionFinished(NioConnector sessionMetadata);
	public void connectionClosedByRemote();
	/*
	 * pckt is not null
	 */
	public void packetReceived(SocketChannel channel, ByteBuffer pckt);

}
