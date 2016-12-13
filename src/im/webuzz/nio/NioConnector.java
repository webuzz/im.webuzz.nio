package im.webuzz.nio;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
//import javax.net.ssl.TrustManagerFactory;
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
	
	public NioConnector(NioSelectorThread st, String address, int port, String domain, boolean usingSSL, boolean usingAvailableProxy, ProtocolDecoder decoder, INioListener processor) {
		this.st = st;
		this.domain = domain;
		this.closed = false;
		if (usingAvailableProxy) {
			checkProxy();
		}
		if (usingAvailableProxy && socksProxyHost != null) {
			this.processor = new NioSocks5Adapter(address, port, usingSSL, decoder, processor);
			this.usingSSL = false;
			this.decoder = null;
			try {
				this.socket = st.addConnection(socksProxyHost, socksProxyPort);
			} catch (Throwable e) {
				e.printStackTrace();
				this.closed = true;
				return;
			}
		} else {
			this.usingSSL = usingSSL;
			this.decoder = decoder;
			this.processor = processor;
			try {
				this.socket = st.addConnection(address, port);
			} catch (Throwable e) {
				e.printStackTrace();
				this.closed = true;
				return;
			}
		}

		//this.inNetBuffer = ByteBuffer.allocate(8192);// = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());

		this.bufferSize = ByteBufferPool.commonBufferSize;
		
		this.st.sessionMap.put(this.socket, this);
		
		// Finally, wake up our selecting thread so it can make the required changes
		this.st.selector.wakeup();
	}
	
	public void send(byte[] data) throws IOException {
		st.send(socket, data);
	}

	public static SSLContext createSSLContext(boolean clientMode, 
			String keystore, String password, final String host) throws Exception {
		// Create/initialize the SSLContext with key material
		char[] passphrase = password.toCharArray();
		// First initialize the key and trust material.
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream fis = new FileInputStream(keystore);
		ks.load(fis, passphrase);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		
		if (clientMode) {
			// TrustManager's decide whether to allow connections.
//			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
//			tmf.init(ks);
//			// KeyManager's decide which key material to use.
//			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
//			kmf.init(ks, passphrase);
//			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			//*
			TrustManager[] trustAllCerts = new TrustManager[] {
					new X509TrustManager() {
						
						@Override
						public X509Certificate[] getAcceptedIssuers() {
							//System.out.println("getAcceptedIssuers");
							return null;
						}
						
						@Override
						public void checkServerTrusted(X509Certificate[] chains, String arg1)
								throws CertificateException {
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
						public void checkClientTrusted(X509Certificate[] arg0, String arg1)
								throws CertificateException {
							//System.out.println("checkClientTrusted " + arg0 + " // " + arg1);
						}
					}
			};
			sslContext.init(null, trustAllCerts, null);
			// */
		} else {
			// KeyManager's decide which key material to use.
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, passphrase);
			sslContext.init(kmf.getKeyManagers(), null, null);
		}
		fis.close();
		return sslContext;
	}

	public void startSSL() {
		//if (decoder != null) {
		//	decoder.reset();
		//}
		
		boolean clientMode = true;
		if (sslContext == null) {
			String javaHome = System.getProperty("java.home");
			StringBuilder buffer = new StringBuilder();
			buffer.append(javaHome).append(File.separator).append("lib");
			buffer.append(File.separator).append("security");
			buffer.append(File.separator).append("cacerts");
			
			String keystore = buffer.toString();
			String password = "changeit";
			try {
				sslContext = createSSLContext(clientMode, keystore, password, domain);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
		}
		engine = sslContext.createSSLEngine();
		engine.setUseClientMode(clientMode);
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

	public void startSSL(SSLContext context) {
		if (decoder != null) {
			decoder.reset();
		}
		
		boolean clientMode = true;
		engine = context.createSSLEngine();
		engine.setUseClientMode(clientMode);

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
		return(this.handshakeTimerTask = new HandshakeTimerTask());
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
