package im.webuzz.nio;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class NioSocks5Adapter implements INioListener {
	
	private String host;
	
	private int port;
	
	private boolean usingSSL;
	
	private ProtocolDecoder decoder;

	private INioListener listener;
	
	private NioConnector connector;
	
	private int state;
	
	private ByteArrayOutputStream baos;
	
	public NioSocks5Adapter(String host, int port, boolean usingSSL, ProtocolDecoder decoder, INioListener listener) {
		super();
		this.host = host;
		this.port = port;
		this.usingSSL = usingSSL;
		this.decoder = decoder;
		this.listener = listener;
	}

	@Override
	public void connectionClosedByRemote() {
		listener.connectionClosedByRemote();
	}

	@Override
	public void connectionFailed(NioConnector sessionMetadata) {
		listener.connectionFailed(sessionMetadata);
	}

	@Override
	public void connectionFinished(NioConnector sessionMetadata) {
		connector = sessionMetadata;
		byte[] greeting = new byte[3];
		greeting[0] = 0x05; // SOCKS v5
		greeting[1] = 0x01; // Length = 1
		greeting[2] = 0x00; // NON
		state = 1;
		try {
			sessionMetadata.send(greeting);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected void sendConnectRequest() {
		byte[] domainBytes = host.getBytes();
		byte[] bytes = new byte[7 + domainBytes.length];
		bytes[0] = 0x05; // SOCKS v5
		bytes[1] = 0x01; // CONNECT
		bytes[2] = 0x00; // RESERVED
		bytes[3] = 0x03; // DOMAIN;
		bytes[4] = (byte) domainBytes.length; //
		System.arraycopy(domainBytes, 0, bytes, 5, domainBytes.length);
		bytes[5 + domainBytes.length] = (byte) (((port & 0xff00) >> 8) & 0xff);
		bytes[6 + domainBytes.length] = (byte) (port & 0xff);
		
		try {
			connector.send(bytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void packetReceived(SocketChannel channel, ByteBuffer pckt) {
		if (state == 3) { // packetReceived
			listener.packetReceived(channel, pckt);
		} else {
			int length = pckt.remaining();
			byte[] array = pckt.array();
			int offset = pckt.arrayOffset();
			if (baos == null) {
				baos = new ByteArrayOutputStream();
			}
			if (state == 1) { // waiting SOCKS v5 greeting response
				int size = baos.size();
				if (length + size >= 2) {
					state = 2;
					baos.reset();
					if (array[offset] != 0xff) {
						sendConnectRequest();
					} else {
						System.out.println("Failed to connect through SOCKS v5");
					}
				} else {
					baos.write(array, offset, length);
				}
			} else if (state == 2) {
				int size = baos.size();
				if (length + size >= 10) {
					state = 3;
					baos.reset();
					if (array[offset + 1] == 0) {
						// connectionFinished
						connector.decoder = decoder;
						if (usingSSL) {
							connector.startSSL();
						}
						listener.connectionFinished(connector);
					} else {
						System.out.println("Got?" + length);
						for (int i = 0; i < length; i++) {
							System.out.println(i + ": " + array[offset + i]);
						}
					}
				} else {
					baos.write(array, offset, length);
				}
			}
		}
	}

	@Override
	public void sslHandshakeFinished() {
		listener.sslHandshakeFinished();
	}

	@Override
	public void sslHandshakeTimeout() {
		listener.sslHandshakeTimeout();
	}

	public INioListener getListener() {
		return listener;
	}

	public void setListener(INioListener listener) {
		this.listener = listener;
	}
	
}
