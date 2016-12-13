package im.webuzz.nio;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class NioAdapter implements INioListener {

	@Override
	public void connectionClosedByRemote() {
	}

	@Override
	public void connectionFailed(NioConnector sessionMetadata) {
	}
	
	@Override
	public void connectionFinished(NioConnector sessionMetadata) {
	}

	@Override
	public void packetReceived(SocketChannel socket, ByteBuffer pckt) {
	}

	@Override
	public void sslHandshakeFinished() {

	}

	@Override
	public void sslHandshakeTimeout() {

	}

}
