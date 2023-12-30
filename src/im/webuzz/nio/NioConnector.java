package im.webuzz.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class NioConnector {
	public SSLEngine engine;
	public ByteBuffer outNetBuffer;
	public ByteBuffer inAppBuffer;
	public ByteBuffer inNetBuffer;
	
	public int bufferSize;
	
	public boolean handshook;
	private TimerTask handshakeTimerTask;

	INioListener processor;
	public SocketChannel socket;
	private boolean handshakeTimeout;
	private NioSelectorThread st;

	ProtocolDecoder decoder;
	
	boolean usingSSL;
	String domain;
	
	private boolean closed;
	
	private SSLContext sslContext;
	
	private static boolean initialized = false;
	
	private static String socksProxyHost;
	
	private static int socksProxyPort;
	
	private static String[] enabledProtocols;
	
	private static String[] enabledCiphers;

	private static void checkProxy() {
		if (initialized) {
			return;
		}
		initialized = true;
		socksProxyHost = System.getProperty("socksProxyHost");
		socksProxyPort = 1080;
		if (socksProxyHost != null) {
			String portStr = System.getProperty("socksProxyPort");
			try {
				socksProxyPort = Integer.parseInt(portStr);
			} catch (NumberFormatException e1) {
			}
		}		
	}
	
	public static void setSOCKS5Proxy(String host, int port) {
		socksProxyHost = host;
		socksProxyPort = port;
		initialized = true;
	}

	public NioConnector(NioSelectorThread st, String address, int port, boolean usingSSL, ProtocolDecoder decoder, INioListener processor) {
		this(st, address, port, address, usingSSL, true, decoder, processor);
	}

	public NioConnector(NioSelectorThread st, String address, int port, boolean usingSSL, boolean usingAvailableProxy, ProtocolDecoder decoder, INioListener processor) {
		this(st, address, port, address, usingSSL, usingAvailableProxy, decoder, processor);
	}
	
	public NioConnector(NioSelectorThread nst, String address, int port, String domain, boolean usingSSL, boolean usingAvailableProxy, ProtocolDecoder decoder, INioListener processor) {
		this.st = nst;
		this.domain = domain;
		if (domain == null) {
			this.domain = address;
		}
		if (this.domain != null) {
			int idx = this.domain.lastIndexOf(':');
			if (idx != -1) {
				this.domain = this.domain.substring(0, idx);
			}
		}
		this.closed = false;

		//this.inNetBuffer = ByteBuffer.allocate(8192);// = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
		this.bufferSize = ByteBufferPool.commonBufferSize;

		if (usingAvailableProxy) {
			checkProxy();
		}
		if (usingAvailableProxy && socksProxyHost != null) {
			this.processor = new NioSocks5Adapter(address, port, usingSSL, decoder, processor);
			this.usingSSL = false;
			this.decoder = null;
			address = socksProxyHost;
			port = socksProxyPort;
		} else {
			this.usingSSL = usingSSL;
			this.decoder = decoder;
			this.processor = processor;
		}
		try {
			this.socket = st.addConnection(address, port);
		} catch (Throwable e) {
			System.out.println("Failed to add connection " + address + ":" + port);
			e.printStackTrace();
			this.closed = true;
			return;
		}
		
		this.st.sessionMap.put(this.socket, this);
		
		// Finally, wake up our selecting thread so it can make the required changes
		this.st.selector.wakeup();
	}
	
	public void send(byte[] data) throws IOException {
		st.send(socket, data);
	}

	public static SSLContext createSSLContext(final String host) throws Exception {
		// Create/initialize the SSLContext with key material
		SSLContext sslContext = SSLContext.getInstance("TLS");
		final NioHostnameVerifier hostVerifier = new NioHostnameVerifier(host);
		TrustManager[] trustAllCerts = new TrustManager[] {
				new X509TrustManager() {

					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}

					@Override
					public void checkServerTrusted(X509Certificate[] chains, String authType)
							throws CertificateException {
						if (!hostVerifier.verify(host, chains)) {
							throw new CertificateException("Invalid certificate.");
						}
						for (X509Certificate cert : chains) {
							boolean hostTrusted = false;
							try {
								VerifyUtils.verify(host, cert);
								hostTrusted = true;
							} catch (SSLException e) {
								e.printStackTrace();
								throw new CertificateException(e);
							}
							cert.checkValidity();
							if (hostTrusted) {
								break;
							}
						}
					}

					@Override
					public void checkClientTrusted(X509Certificate[] chains, String authType)
							throws CertificateException {
						//System.out.println("checkClientTrusted " + chains + " // " + authType);
					}
				}
		};
		sslContext.init(null, trustAllCerts, null);
		return sslContext;
	}

	public void startSSL() {
		//if (decoder != null) {
		//	decoder.reset();
		//}
		
		if (sslContext == null) {
			try {
				sslContext = createSSLContext(domain);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
		}
		engine = sslContext.createSSLEngine();
		engine.setUseClientMode(true);
		engine.setNeedClientAuth(true);
		
		if (enabledProtocols != null) {
			engine.setEnabledProtocols(enabledProtocols);
		} else {
			String[] protocols = engine.getSupportedProtocols();
			if (protocols != null && protocols.length > 0) {
				String[] ps = NioConfig.sslProtocols;
				if (ps != null && ps.length > 0) {
					List<String> matchedProtocols = new ArrayList<String>(ps.length);
					for (String p : ps) {
						if (p == null) continue;
						for (String protocol : protocols) {
							if (p.equals(protocol)) {
								matchedProtocols.add(protocol);
								break;
							}
						}
					}
					int size = matchedProtocols.size();
					if (size > 0) {
						enabledProtocols = matchedProtocols.toArray(new String[size]);
						engine.setEnabledProtocols(enabledProtocols);
					}
				}
			}
		}
		if (enabledCiphers != null) {
			engine.setEnabledCipherSuites(enabledCiphers);
		} else {
			String[] ciphers = engine.getSupportedCipherSuites();
			if (ciphers != null && ciphers.length > 0) {
				String[] cs = NioConfig.sslCipherSuites;
				if (cs != null && cs.length > 0) {
					List<String> matchedCiphers = new ArrayList<String>(cs.length);
					for (String c : cs) {
						if (c == null) continue;
						for (String cipher : ciphers) {
							if (c.equals(cipher)) {
								matchedCiphers.add(cipher);
								break;
							}
						}
					}
					int size = matchedCiphers.size();
					if (size > 0) {
						enabledCiphers = matchedCiphers.toArray(new String[size]);
						engine.setEnabledCipherSuites(enabledCiphers);
					}
				}
			}
		}
		//engine.setEnabledProtocols(NioConfig.sslProtocols);
		//engine.setEnabledCipherSuites(NioConfig.sslCipherSuites);
		engine.setEnableSessionCreation(NioConfig.sslSessionCreation);

		if (NioConfig.sslSupportsSNI) {
			try {
				SSLParameters sslParameters = engine.getSSLParameters();
				SNIServerName hostName = new SNIHostName(domain);
				List<SNIServerName> list = new ArrayList<SNIServerName>();
				list.add(hostName);
				sslParameters.setServerNames(list);
				engine.setSSLParameters(sslParameters);
			} catch (Throwable e) {
				e.printStackTrace();
			}
		}

		this.closed = false;
		
//		this.outNetBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
//		this.inNetBuffer = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
//		this.inAppBuffer = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
		
		this.outNetBuffer = null;
		this.inNetBuffer = null;
		this.inAppBuffer = null;
		this.bufferSize = Math.max(engine.getSession().getPacketBufferSize(), engine.getSession().getApplicationBufferSize());
		
		this.handshook = false;
		usingSSL = true;

		// Create SSL metadata container (this will initialize relevant buffers too)

		try {
			engine.beginHandshake();
		} catch (SSLException e) {
			e.printStackTrace();
		}
	
		int timeout = 30000;
		if (timeout != 0) {
			st.getTimer().schedule(newHandshakeTimerTask(), timeout);
		}
	}

	public INioListener getProcessor() {
		return processor;
	}

	public void setProcessor(INioListener processor) {
		if (this.processor instanceof NioSocks5Adapter) { // SOCKS5
			((NioSocks5Adapter) this.processor).setListener(processor);
		} else {
			this.processor = processor;
		}
	}

	public void remoteClose() {
		if (socket != null && st != null) {
			try {
				st.send(socket, null);
			} catch (IOException e) {
				//e.printStackTrace();
			}
		}
	}
	
	public void close() {
		this.close(false);
	}
	
	public void close(boolean remoteClosing) {
		if (closed) {
			return;
		}
		closed = true;
		if (engine != null) {
			engine.closeOutbound();
//			try {
//				engine.closeInbound();
//			} catch (SSLException e) {
//				e.printStackTrace();
//			}
//			engine = null;
			if (!remoteClosing && !engine.isOutboundDone()) {
				st.writeSSLDummyPacket(this, socket);
			}
		}
		if (socket != null) {
			SelectionKey key = socket.keyFor(st.selector);
			if (key != null) {
				key.cancel();
			}
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	public TimerTask newHandshakeTimerTask() {
		return (this.handshakeTimerTask = new HandshakeTimerTask());
	}
	
	public void cancelHandshakeTimer() {
		if (this.handshakeTimerTask != null) {
			this.handshakeTimerTask.cancel();
		}
	}
	
	public boolean handshakeTimeout() {
		return this.handshakeTimeout;
	}
	
	private class HandshakeTimerTask extends TimerTask {
		public void run() {
			handshakeTimeout = true;
			
			processor.sslHandshakeTimeout();
		}
	}

	public boolean isClosed() {
		return closed;
	}
}
