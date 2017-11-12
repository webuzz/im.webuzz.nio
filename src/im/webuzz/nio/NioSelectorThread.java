package im.webuzz.nio;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.util.Date;
import java.util.HashMap;
//import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

public class NioSelectorThread implements Runnable {

	// An empty buffer used as the source buffer for wrap() operations during
	// SSL handshakes.
	private static ByteBuffer BLANK = ByteBuffer.allocate(0);

	// The selector we'll be monitoring
	Selector selector;

	// A list of PendingChange instances
	private List<ChangeRequest> pendingChanges = new LinkedList<ChangeRequest>();

	// Maps a SocketChannel to a list of ByteBuffer instances
	private Map<SocketChannel, LinkedList<ByteBuffer>> pendingData = new HashMap<SocketChannel, LinkedList<ByteBuffer>>();
	
	Map<SocketChannel, NioConnector> sessionMap = new ConcurrentHashMap<SocketChannel, NioConnector>();

	private static Map<String, NioSelectorThread> selectors = new HashMap<String, NioSelectorThread>();
	
	private Timer timer;
	
	private boolean running;

	private ExecutorService exec;
	
	private String id;

	private long processCount = 0;
	
	private long getPoolCount = 0;
	
	private long putPoolCount = 0;
	
	private long loopCount = 0;
	
	private long readCount = 0;
	
	private long writeCount = 0;
	
	private long readBytes = 0;
	
	private long writeBytes = 0;
	
	public static String printAllKeyStatuses(String key) {
		StringBuilder builder = new StringBuilder();
		NioSelectorThread nst = selectors.get(key);
		if (nst != null) {
			builder.append("SessionMap size = " + nst.sessionMap.size());
			builder.append("<br />\r\n");
			builder.append("PendingData size = " + nst.pendingData.size());
			builder.append("<br />\r\n");
			builder.append("PendingChange size = " + nst.pendingChanges.size());
			builder.append("<br />\r\n");
			builder.append("Process count = " + nst.processCount);
			builder.append("<br />\r\n");
			builder.append("Loop count = " + nst.loopCount);
			builder.append("<br />\r\n");
			builder.append("Read count = " + nst.readCount);
			builder.append("<br />\r\n");
			builder.append("Write count = " + nst.writeCount);
			builder.append("<br />\r\n");
			builder.append("Read bytes = " + nst.readBytes);
			builder.append("<br />\r\n");
			builder.append("Write bytes = " + nst.writeBytes);
			builder.append("<br />\r\n");
			builder.append("Pooling getting count = " + nst.getPoolCount);
			builder.append("<br />\r\n");
			builder.append("Pooling putting count = " + nst.putPoolCount);
			builder.append("<br />\r\n");
			builder.append("Pool total alloc count = " + ByteBufferPool.allocateCount);
			builder.append("<br />\r\n");
			builder.append("Pool pooled count = " + ByteBufferPool.pooledCount);
			builder.append("<br />\r\n");
			builder.append("Pool spare count = " + ByteBufferPool.pooledBufferSpareCount);
			builder.append("<br />\r\n");
//			int count = 0;
			Set<SelectionKey> keys = nst.selector.keys();
			int i = 0;
			for (Iterator<SelectionKey> itr = keys.iterator(); itr
					.hasNext();) {
				SelectionKey k = (SelectionKey) itr.next();
				if (!k.isValid()) {
					System.out.println("Key " + k + " invalid.");
					continue;
				}
				NioConnector connector = nst.sessionMap.get(k.channel());
				builder.append(i + ":" + /*connector.appBufferSize + " | " + connector.packetBufferSize + " | " + */(connector.inNetBuffer == null) + " | " + (connector.outNetBuffer == null) + " // " + ByteBufferPool.allocateCount + " | " + ByteBufferPool.pooledCount + "<br />\r\n");
				builder.append(i + ": " + k.interestOps() + " | " + k.readyOps()
						+ " | " + k.isAcceptable()
						+ " | " + k.isConnectable()
						+ " | " + k.isReadable()
						+ " | " + k.isWritable()
						+ " | " + k.isValid() + " // " + k + " <br />\r\n");
				i++;
			}
		} else {
			builder.append("Not initialized.<br />\r\n");
		}
		return builder.toString();
	}
	
	public static NioSelectorThread getNioSelectorThread(String id) {
		NioSelectorThread thread = null;
		synchronized (selectors) {
			thread = selectors.get(id);
			if (thread == null) {
				thread = new NioSelectorThread(id);
			}
			selectors.put(id, thread);
		}
		return thread;
	}
	
	private NioSelectorThread(String id) {
		this.id = id;
		try {
			this.selector = SelectorProvider.provider().openSelector();
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		exec = Executors.newSingleThreadExecutor(new NamedThreadFactory("NIO Delegated Task Thread"));

		Thread t = new Thread(this, "NIO Selector Thread - " + id);
		t.setDaemon(true);
		t.start();
	}

	public void send(SocketChannel socket, byte[] data) throws IOException {
		if (data == null || data.length == 0) {
			synchronized (this.pendingChanges) {
				this.pendingChanges.add(new ChangeRequest(socket, ChangeRequest.CLOSE, -1));
			}
			this.selector.wakeup();
			return;
		}

		// And queue the data we want written
		synchronized (this.pendingData) {
			LinkedList<ByteBuffer> queue = (LinkedList<ByteBuffer>) this.pendingData.get(socket);
			if (queue == null) {
				queue = new LinkedList<ByteBuffer>();
				this.pendingData.put(socket, queue);
			}
			queue.add(ByteBuffer.wrap(data));
		}

		synchronized (this.pendingChanges) {
			// Indicate we want the interest ops set changed
			this.pendingChanges.add(new ChangeRequest(socket, ChangeRequest.CHANGEOPS, SelectionKey.OP_WRITE));
		}

		// Finally, wake up our selecting thread so it can make the required changes
		this.selector.wakeup();
	}

	public void stop() {
		running = false;
		if (selector != null) {
			selector.wakeup();
		}
		if (id != null) {
			synchronized (selectors) {
				selectors.remove(id);
			}
		}
	}
	
	public void run() {
		boolean firstTimeError = true;
		int count = 0;
		running = true;
		
		ChangeRequest[] pendingArray = null;
		int pendingSize = 0;
		while (running) {
			try {
				// Process any pending changes
				synchronized (this.pendingChanges) {
					pendingSize = this.pendingChanges.size();
					if (pendingSize > 0) {
						if (pendingArray == null || pendingArray.length < pendingSize) {
							pendingArray = new ChangeRequest[pendingSize];
						}
						this.pendingChanges.toArray(pendingArray);
						this.pendingChanges.clear();
					}
				}
				for (int i = 0; i < pendingSize; i++) {
					ChangeRequest change = pendingArray[i];
					try {
						switch (change.type) {
						case ChangeRequest.CHANGEOPS:
							SelectionKey key = change.socket.keyFor(this.selector);
							if (key == null) {
								try {
									change.socket.close();
								} catch (Throwable e) {
									e.printStackTrace();
								}
								continue;
							}
							if (!key.isValid()) {
								continue; // ignore...
							}
							if ((key.interestOps() & SelectionKey.OP_CONNECT) != 0) {
								key.interestOps(change.ops | SelectionKey.OP_CONNECT);
							} else {
								key.interestOps(change.ops);
							}
							break;
						case ChangeRequest.REGISTER:
							/*SelectionKey registerKey = */change.socket.register(this.selector, change.ops);
							break;
						case ChangeRequest.CLOSE:
							SelectionKey closeKey = change.socket.keyFor(this.selector);
							if (closeKey != null) {
								safeClose(closeKey, change.socket, false);
							} else {
								try {
									change.socket.close();
								} catch (Throwable e) {
									e.printStackTrace();
								}
							}
							break;
						}
					} catch (Exception e) {
						e.printStackTrace();
						printKeyStatus();

						try {
							SelectionKey key = change.socket.keyFor(this.selector);
							if (key != null) {
								safeClose(key, null, false);
							} else {
								try {
									change.socket.close();
								} catch (Throwable e1) {
									e1.printStackTrace();
								}
							}
						} catch (Throwable ee) {
							ee.printStackTrace();
						}
					}
				}
				
				loopCount++;
				// Wait for an event one of the registered channels
				/*int ns = */this.selector.select();
				if (!running) {
					break;
				}
				Set<SelectionKey> readyKeys = null;
				readyKeys = this.selector.selectedKeys();

				/*int size = */readyKeys.size();
				count++;
				
				if (count % 40 == 39) {
					if (firstTimeError) {
						firstTimeError = false;
					}
					//int ns = selector.selectNow();
					printKeyStatus();
					try {
						Thread.sleep(10);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				
				//int removedCount = 0;
				// Iterate over the set of keys for which events are available
				Iterator<SelectionKey> selectedKeys = readyKeys.iterator();
				while (selectedKeys.hasNext()) {
					SelectionKey key = (SelectionKey) selectedKeys.next();
					selectedKeys.remove();
					//removedCount++;
					count = 0;
					
					if (!key.isValid()) {
						continue;
					}

					try {
						// Obtain the interest of the key
						int readyOps = key.readyOps();
						// Disable the interest for the operation that is ready.
						// This prevents the same event from being raised multiple 
						// times.
						key.interestOps(key.interestOps() & ~readyOps);
						
						// Check what event is available and deal with it
						if (key.isConnectable()) {
							this.finishConnection(key);
						} else if (key.isReadable()) {
							this.read(key);
						} else if (key.isWritable()) {
							this.write(key);
						} else {
							//System.out.println("What? Should not happen!!!");
						}
						
						if (key.isValid() && key.interestOps() == 0) {
							System.out.println("Close because no operator registered!");
							safeClose(key, null, false);
						}
					} catch (Throwable e) {
						e.printStackTrace();
						safeClose(key, null, false);
					}
				}
			} catch (Exception e) {
				System.out.println("The Outer exception!");
				e.printStackTrace();
				printKeyStatus();
			}
		}
		if (selector != null) {
			closeSelectorAndChannels();
		}
	}

	private void closeSelectorAndChannels() {
		Set<SelectionKey> keys = selector.keys();
		for (Iterator<SelectionKey> iter = keys.iterator(); iter.hasNext();) {
			SelectionKey key = (SelectionKey) iter.next();
			try {
				key.channel().close();
			} catch (IOException e) {
				// Ignore
			}
		}
		try {
			selector.close();
		} catch (IOException e) {
			// Ignore
		}
		if (timer != null) {
			timer.cancel();
		}
		exec.shutdown();
	}

	private void printKeyStatus() {
		Set<SelectionKey> keys = selector.keys();
		//int i = 0;
		for (Iterator<SelectionKey> itr = keys.iterator(); itr
				.hasNext();) {
			SelectionKey k = (SelectionKey) itr.next();
			if (!k.isValid()) {
				continue;
			}
			//i++;
		}
		System.out.println("print key size = " + keys.size() + " // " + new Date());
	}

	public SocketChannel addConnection(String address, int port) throws IOException {
		// Create a non-blocking socket channel
		SocketChannel socketChannel = SocketChannel.open();
		socketChannel.configureBlocking(false);

		// Kick off connection establishment
		socketChannel.connect(new InetSocketAddress(address, port));
		processCount++;
		
		// Queue a channel registration since the caller is not the 
		// selecting thread. As part of the registration we'll register
		// an interest in connection events. These are raised when a channel
		// is ready to complete connection establishment.
		synchronized(this.pendingChanges) {
			this.pendingChanges.add(new ChangeRequest(socketChannel, ChangeRequest.REGISTER, SelectionKey.OP_CONNECT));
		}
		
		return socketChannel;
	}

	private void finishConnection(SelectionKey key) throws IOException {
		SocketChannel socketChannel = (SocketChannel) key.channel();
		// Finish the connection. If the connection operation failed
		// this will raise an IOException.
		try {
			if (!socketChannel.finishConnect()) {
				// http://stackoverflow.com/questions/9912509/sending-multiple-messages-through-only-one-socketchannel
				return;
			}
			processCount++;
		} catch (IOException e) {
			String message = e.getMessage();
			if (message != null
					&& message.indexOf("Connection timed out") == -1
					&& message.indexOf("Connection refused") == -1) {
				e.printStackTrace();
			}
			// Cancel the channel's registration with our selector
			key.cancel();
			NioConnector sessionMetadata = (NioConnector) this.sessionMap.get(socketChannel);
			if (sessionMetadata != null) {
				try {
					sessionMetadata.processor.connectionFailed(sessionMetadata);
				} catch (Throwable ee) {
					ee.printStackTrace();
				}
				this.sessionMap.remove(socketChannel);
				synchronized (pendingData) {
					this.pendingData.remove(socketChannel);
				}
			}
			return;
		}
		NioConnector sessionMetadata = (NioConnector) this.sessionMap.get(socketChannel);
		if (sessionMetadata == null) {
			safeClose(key, socketChannel, false);
			return;
		}

		//boolean interestedInWriting = false;
		synchronized (this.pendingData) {
			List<ByteBuffer> queue = (List<ByteBuffer>) this.pendingData.get(socketChannel);
			boolean interestedInWriting = queue != null && !queue.isEmpty();
			if (interestedInWriting || sessionMetadata.usingSSL) {
				// Register an interest in writing on this channel
				key.interestOps(SelectionKey.OP_WRITE);
			} else {
				key.interestOps(SelectionKey.OP_READ);
			}
		}

		if (sessionMetadata.usingSSL) {
			sessionMetadata.startSSL();
		}
		
		if (sessionMetadata.processor != null) {
			try {
				sessionMetadata.processor.connectionFinished(sessionMetadata);
			} catch (Throwable e) {
				e.printStackTrace();
			}
		}
	}

	protected Timer getTimer() {
		// Create this Timer lazily so if callers never use timeouts they 
		// don't have the overhead of an extra thread per client instance.
		if (timer == null) {
			timer = new Timer("SSL Handshake Timeout Monitor", true);
		}
		return timer;
	}

	protected void read(SelectionKey key) throws IOException {
		readCount++;
		SocketChannel socketChannel = (SocketChannel) key.channel();
		NioConnector sessionMetadata = (NioConnector) this.sessionMap.get(socketChannel);
		boolean gotData = false;
		if (sessionMetadata.usingSSL) {
			int hsResult = checkSSLHandshake(sessionMetadata, key, socketChannel, SelectionKey.OP_READ);
			if (hsResult <= 0) {
				return;
			} else if (hsResult == 2) { // For OP_READ, we will make sure data is ready
				gotData = true;
				// continue ...
			} // else continue ...
		}
		
		if (sessionMetadata.inNetBuffer == null) {
			sessionMetadata.inNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
			getPoolCount++;
		}
		ByteBuffer inNetBuffer = sessionMetadata.inNetBuffer;
		if (!gotData) {
			int numRead = -1;
			try {
				numRead = socketChannel.read(inNetBuffer);
				processCount++;
			} catch (IOException e) {
				String message = e.getMessage();
				if (message.indexOf("Connection reset by peer") == -1
						&& message.indexOf("Broken pipe") == -1
						&& message.indexOf("closed by the remote host") == -1
						&& message.indexOf("connection was aborted") == -1) {
					e.printStackTrace();
				}
				numRead = -1;
			}
			if (numRead == -1) {
				// Remote entity shut the socket down cleanly. Do the
				// same from our end and cancel the channel.
				if (sessionMetadata.processor != null) {
					try {
						sessionMetadata.processor.connectionClosedByRemote();
					} catch (Throwable e) {
						e.printStackTrace();
					}
				}
				safeClose(key, socketChannel, true);
				return;
			}
			if (numRead == 0) {
				interestNext(key, socketChannel);
				return;
			}
			readBytes += numRead;
		}

		if (sessionMetadata.usingSSL) {
			inNetBuffer.flip();
			if (sessionMetadata.inAppBuffer == null) {
				sessionMetadata.inAppBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
				getPoolCount++;
			}
			ByteBuffer inAppBuffer = sessionMetadata.inAppBuffer;
			boolean processed = false;
			while (inNetBuffer.hasRemaining()) {
				if (sessionMetadata.engine == null) {
					throw new IOException("SSL Engine being null?");
				}
				SSLEngineResult result = null;
				try {
					result = sessionMetadata.engine.unwrap(inNetBuffer, inAppBuffer);
					processCount++;
				} catch (SSLException e) {
					e.printStackTrace();
					safeClose(key, socketChannel, true);
					return;
				}
				inAppBuffer.flip();
				if (inAppBuffer.hasRemaining()) {
					if (!dataReceived(sessionMetadata, socketChannel, inAppBuffer)) {
						safeClose(key, socketChannel, false);
						return;
					}
					processed = true;
				}
				inAppBuffer.clear();
				if (result != null) {
					Status rsStatus = result.getStatus();
					if (rsStatus == Status.BUFFER_UNDERFLOW) {
						break;
					} else if (rsStatus == Status.CLOSED) {
						safeClose(key, socketChannel, true);
						return;
					}
				}
			}
			if (!processed) {
				inAppBuffer.flip();
				if (inAppBuffer.hasRemaining()) {
					if (!dataReceived(sessionMetadata, socketChannel, inAppBuffer)) {
						safeClose(key, socketChannel, false);
						return;
					}
				}
				inAppBuffer.clear();
			}
			
			// Compact our read buffer after we've handled the data instead of before
			// we read so that during the SSL handshake we can deal with the BUFFER_UNDERFLOW
			// case by simple waiting for more data (which will be appended into this buffer).
			if (inNetBuffer.hasRemaining()) {
				inNetBuffer.compact();
			} else {
				//inNetBuffer.clear();
				if (sessionMetadata.inNetBuffer == inNetBuffer) {
					sessionMetadata.inNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(inNetBuffer);
				putPoolCount++;
			}
		} else { // plain connection
			inNetBuffer.flip();
			if (!dataReceived(sessionMetadata, socketChannel, inNetBuffer)) {
				safeClose(key, socketChannel, false);
				return;
			}
			//inNetBuffer.clear();
			if (sessionMetadata.inNetBuffer == inNetBuffer) {
				sessionMetadata.inNetBuffer = null;
			}
			ByteBufferPool.putByteBufferToPool(inNetBuffer);
			putPoolCount++;
		} // end of plain connection
		
		interestNext(key, socketChannel);
	}

	private boolean dataReceived(NioConnector sessionMetadata,
			SocketChannel socketChannel, ByteBuffer buffer) {
		try {
			if (sessionMetadata.decoder != null) {
				do {
					ByteBuffer decodedPacket = sessionMetadata.decoder.decode(buffer);
					if (decodedPacket != null) {
						sessionMetadata.processor.packetReceived(socketChannel, decodedPacket);
					}
				} while (buffer.hasRemaining());
			} else {
				sessionMetadata.processor.packetReceived(socketChannel, buffer);
			}
		} catch (Throwable e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	private void interestNext(SelectionKey key, SocketChannel socketChannel) {
		if (!key.isValid()) {
			safeClose(key, socketChannel, true);
			return;
		}
		boolean interestedInWriting = false;
		synchronized (this.pendingData) {
			List<ByteBuffer> queue = (List<ByteBuffer>) this.pendingData.get(socketChannel);
			interestedInWriting = queue != null && !queue.isEmpty();
		}
		if (interestedInWriting) {
			// Register an interest in writing on this channel
			key.interestOps(SelectionKey.OP_WRITE);
		} else {
			key.interestOps(SelectionKey.OP_READ);
		}
	}

	private void safeClose(SelectionKey key, SocketChannel socketChannel, boolean remoteClosing) {
		if (key == null) {
			if (socketChannel != null) {
				sessionMap.remove(socketChannel);
			}
			return;
		}
		if (socketChannel == null) {
			socketChannel = (SocketChannel) key.channel();
			if (socketChannel == null) {
				key.cancel();
				return;
			}
		}
		synchronized (pendingData) {
			pendingData.remove(socketChannel);
		}
		NioConnector sessionMetadata = sessionMap.get(socketChannel);
		if (sessionMetadata != null) {
			sessionMetadata.close(remoteClosing);
			sessionMap.remove(socketChannel);
			
			if (sessionMetadata.inAppBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.inAppBuffer);
				sessionMetadata.inAppBuffer = null;
				putPoolCount++;
			}
			if (sessionMetadata.inNetBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.inNetBuffer);
				sessionMetadata.inNetBuffer = null;
				putPoolCount++;
			}
			if (sessionMetadata.outNetBuffer != null) {
				ByteBufferPool.putByteBufferToPool(sessionMetadata.outNetBuffer);
				sessionMetadata.outNetBuffer = null;
				putPoolCount++;
			}
		}
		Socket socket = socketChannel.socket();
		key.cancel();
		try {
			socket.shutdownOutput();
		} catch (Exception e) {
			//e.printStackTrace();
		}
		try {
			socket.shutdownInput();
		} catch (Exception e) {
			//e.printStackTrace();
		}
		try {
			socketChannel.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
		if (sessionMetadata != null && sessionMetadata.decoder != null) {
			try {
				ByteBuffer decodedPacket = sessionMetadata.decoder.decode(null);
				if (decodedPacket != null) {
					sessionMetadata.processor.packetReceived(socketChannel, decodedPacket);
				}
			} catch (Throwable e) {
				e.printStackTrace();
			}
		}
	}

	/*
	 * Return SSL handshake checking result.
	 * -1: Error
	 * 0: Still need handshakes
	 * 1: Need no handshakes
	 * 2: Handshake finished, continue following operations
	 */
	private int checkSSLHandshake(NioConnector sessionMetadata, SelectionKey key, SocketChannel socketChannel,
			int inOperation) {
		if (sessionMetadata == null || sessionMetadata.engine == null) {
			safeClose(key, socketChannel, false);
			return -1;
		}
		boolean handshaking = !sessionMetadata.handshook;
		if (handshaking) {
			HandshakeStatus hsStatus = sessionMetadata.engine.getHandshakeStatus();
			handshaking = (hsStatus != HandshakeStatus.NOT_HANDSHAKING && hsStatus != HandshakeStatus.FINISHED);
			if (!handshaking) {
				sessionMetadata.handshook = true;
				sessionMetadata.cancelHandshakeTimer();
			}
		}
		if (handshaking) {
			try {
				if (this.progressSSLHandshake(sessionMetadata, key, socketChannel, inOperation)) {
					return 2; // just finished handshake, continue
				} else {
					return 0; // still need handshake
				}
			} catch (IOException e) {
				e.printStackTrace();
				if (sessionMetadata.processor != null) {
					try {
						sessionMetadata.processor.connectionClosedByRemote();
					} catch (Throwable ex) {
						ex.printStackTrace();
					}
				}
				safeClose(key, socketChannel, true);
				return -1;
			}
		}
		return 1; // need no handshake
	}
	
	protected void write(SelectionKey key) throws IOException {
		writeCount++;
		SocketChannel socketChannel = (SocketChannel) key.channel();

		NioConnector sessionMetadata = (NioConnector) this.sessionMap.get(socketChannel);
		if (sessionMetadata.usingSSL) {
			int hsResult = checkSSLHandshake(sessionMetadata, key, socketChannel, SelectionKey.OP_WRITE);
			if (hsResult <= 0) { // error, or still need handshakes
				return;
			}
		}

		ByteBuffer buf = null;
		boolean queueAlreadyEmpty = false;
		List<ByteBuffer> queue = null;
		synchronized (this.pendingData) {
			queue = (List<ByteBuffer>) this.pendingData.get(socketChannel);
			if (queue != null) {
				if (!queue.isEmpty()) {
					buf = (ByteBuffer) queue.get(0);
					if (buf.capacity() == 0) {
						pendingData.remove(socketChannel);
						queue.remove(0);
						queue = null;
					} // else continue
				} else {
					queueAlreadyEmpty = true; // try to read from channel instead
				}
			} else {
				pendingData.remove(socketChannel);
			}
		} // end of synchronized
		
		if (queue == null) {
			safeClose(key, socketChannel, false);
			return;
		}
		if (queueAlreadyEmpty) {
			key.interestOps(SelectionKey.OP_READ);
			return;
		}
		
		// queue not empty with at least one buffer
		int numWritten = -1;
		ByteBuffer outNetBuffer = null;
		if (sessionMetadata.usingSSL) {
			if (buf.hasRemaining()) {
				if (sessionMetadata.outNetBuffer == null) {
					sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
					getPoolCount++;
				}
				outNetBuffer = sessionMetadata.outNetBuffer;
				/*SSLEngineResult result = */sessionMetadata.engine.wrap(buf, outNetBuffer);
				processCount++;
			} else {
				outNetBuffer = sessionMetadata.outNetBuffer; // should always be not null!
			}
			outNetBuffer.flip();
		}
		
		try {
			numWritten = socketChannel.write(sessionMetadata.usingSSL ? outNetBuffer : buf);
			processCount++;
		} catch (Throwable e) {
			String message = e.getMessage();
			if (message != null && message.indexOf("Connection reset by peer") == -1
					&& message.indexOf("Broken pipe") == -1
					&& message.indexOf("connection was forcibly closed") == -1) {
				e.printStackTrace();
			}
			numWritten = -1;
		}
		
		if (numWritten < 0) {
			if (sessionMetadata.processor != null) {
				try {
					sessionMetadata.processor.connectionClosedByRemote();
				} catch (Throwable e) {
					e.printStackTrace();
				}
			}
			safeClose(key, socketChannel, true);
			return;
		}
		
		writeBytes += numWritten;
		
		if (sessionMetadata.usingSSL && outNetBuffer.hasRemaining()) { // partly sent
			outNetBuffer.compact();
			key.interestOps(SelectionKey.OP_WRITE);
		} else {
			if (sessionMetadata.usingSSL) {
				//outNetBuffer.clear();
				if (sessionMetadata.outNetBuffer == outNetBuffer) {
					sessionMetadata.outNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(outNetBuffer);
				putPoolCount++;
			}
			if (buf.hasRemaining()) {
				// schedule write operation for next time
				// try to write all data in the buffer may cause freezing,
				// or may freeze other connections
				key.interestOps(SelectionKey.OP_WRITE);
			} else {
				boolean interestingWriting = false;
				synchronized (this.pendingData) {
					if (!queue.isEmpty()) {
						queue.remove(0);
					}
					interestingWriting = !queue.isEmpty();
				}
				key.interestOps(interestingWriting ? SelectionKey.OP_WRITE : SelectionKey.OP_READ);
			}
		} // end of if-else of partly sent
	}

	/*
	 * Return whether SSL handshake is finished and next operation should be performed.
	 */
	private boolean progressSSLHandshake(NioConnector sessionMetadata, SelectionKey key, SocketChannel socketChannel,
			int inOperation) throws IOException {
		SSLEngine engine = sessionMetadata.engine;
		
		//SSLEngineResult result;
		while(true) {
			switch(engine.getHandshakeStatus()) {
			case FINISHED:
			case NOT_HANDSHAKING:
				sessionMetadata.handshook = true;
				sessionMetadata.cancelHandshakeTimer();
				if (sessionMetadata.processor != null) {
					try {
						sessionMetadata.processor.sslHandshakeFinished();
					} catch (Throwable e) {
						e.printStackTrace();
					}
				}
				if (inOperation == SelectionKey.OP_WRITE) {
					return true;
				} else {
					interestNext(key, socketChannel);
					return false;
				}
			case NEED_TASK:
				this.delegateSSLEngineTasks(socketChannel, engine);
				break;
			case NEED_UNWRAP: {
				if (inOperation == SelectionKey.OP_WRITE) {
					key.interestOps(SelectionKey.OP_READ);
					return false;
				}
				// Since the handshake needs an unwrap() and we're only in here because of either
				// a read and a write, we assume(!) we're in here because of a read and that
				// data is available.
				if (sessionMetadata.inNetBuffer == null) {
					sessionMetadata.inNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
					getPoolCount++;
				}
				ByteBuffer inNetBuffer = sessionMetadata.inNetBuffer;
				int numRead = socketChannel.read(inNetBuffer);
				if (numRead < 0) {
					throw new SSLException("Handshake aborted by remote entity (socket closed)");
				}
				
				if (numRead == 0 && engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP) {
					// Bail so we go back to blocking the selector
					
					// Since we're in here the channel is already registered for OP_READ.
					// Don't re-queue it since that will needlessly wake up the selecting
					// thread.
					key.interestOps(SelectionKey.OP_READ);
					return false;
				}
				
				readBytes += numRead;
				
				inNetBuffer.flip();
				ByteBuffer inAppBuffer = null;
				if (inNetBuffer.hasRemaining()) {
					if (sessionMetadata.inAppBuffer == null) {
						sessionMetadata.inAppBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
						getPoolCount++;
					}
					inAppBuffer = sessionMetadata.inAppBuffer;
				}
				int unwrapCount = 0;
				while (inNetBuffer.hasRemaining()) {
					SSLEngineResult result = engine.unwrap(inNetBuffer, inAppBuffer);
					unwrapCount++;
					if (unwrapCount > 1000000) {
						Status rsStatus = result.getStatus();
						System.out.println("Handshake status: " + rsStatus.ordinal() + "/" + rsStatus.name() + " " + rsStatus);
						System.out.println("Handshake buffer: " + inNetBuffer.remaining() + " vs " + inAppBuffer.remaining() + " " + inAppBuffer.position());
						HandshakeStatus hsStatus = engine.getHandshakeStatus();
						System.out.println("Engine status: " + hsStatus.ordinal() + "/" + hsStatus.name() + " " + hsStatus);
						throw new SSLException("Handshake unwrap too many times!");
					}
					processCount++;
					
					HandshakeStatus hsStatus = engine.getHandshakeStatus();
					if (hsStatus == HandshakeStatus.NEED_TASK) {
						this.delegateSSLEngineTasks(socketChannel, engine);
					}
					
					Status rsStatus = result.getStatus();
					if (rsStatus == Status.BUFFER_UNDERFLOW) {
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
							putPoolCount++;
						}
						key.interestOps(SelectionKey.OP_READ);
						return false;
					} else if (rsStatus != Status.OK) {
						if (rsStatus == Status.CLOSED) {
							throw new SSLException("Handshake closed by remote entity");
						} else if (rsStatus == Status.BUFFER_OVERFLOW) {
							throw new SSLException("Handshake unwrap overflow!");
						} else { // Unkown status
							throw new SSLException("Handshake unwrap unkown error (" + rsStatus.ordinal() + "/" + rsStatus + "!");
						}
					}

					// Status OK
					if (inAppBuffer.position() > 0) { // A handshake already produces data for us to consume.
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
							putPoolCount++;
						}
						sessionMetadata.handshook = true;
						sessionMetadata.cancelHandshakeTimer();
						if (sessionMetadata.processor != null) {
							try {
								sessionMetadata.processor.sslHandshakeFinished();
							} catch (Throwable e) {
								e.printStackTrace();
							}
						}
						return true; // continue to read or write data
					}

					if (hsStatus == HandshakeStatus.FINISHED || hsStatus == HandshakeStatus.NOT_HANDSHAKING) {
						if (unwrapCount > 100000) {
							System.out.println("Handshake unwrap takes " + unwrapCount + " to finish");
						}
						if (inNetBuffer.hasRemaining()) {
							inNetBuffer.compact();
							sessionMetadata.handshook = true;
							sessionMetadata.cancelHandshakeTimer();
							if (sessionMetadata.processor != null) {
								try {
									sessionMetadata.processor.sslHandshakeFinished();
								} catch (Throwable e) {
									e.printStackTrace();
								}
							}
							return true; // continue to read or write data
						} else {
							//inNetBuffer.clear();
							if (sessionMetadata.inNetBuffer == inNetBuffer) {
								sessionMetadata.inNetBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inNetBuffer);
							putPoolCount++;
							if (sessionMetadata.inAppBuffer == inAppBuffer) {
								sessionMetadata.inAppBuffer = null;
							}
							ByteBufferPool.putByteBufferToPool(inAppBuffer);
							putPoolCount++;
							if (sessionMetadata.processor != null) {
								try {
									sessionMetadata.processor.sslHandshakeFinished();
								} catch (Throwable e) {
									e.printStackTrace();
								}
							}
							if (inOperation == SelectionKey.OP_WRITE) {
								return true;
							} else {
								interestNext(key, socketChannel);
								return false;
							}
						}
					}
					
				} // end of while
				//inNetBuffer.clear();
				if (sessionMetadata.inNetBuffer == inNetBuffer) {
					sessionMetadata.inNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(inNetBuffer);
				putPoolCount++;
				if (inAppBuffer != null) {
					if (sessionMetadata.inAppBuffer == inAppBuffer) {
						sessionMetadata.inAppBuffer = null;
					}
					ByteBufferPool.putByteBufferToPool(inAppBuffer);
					putPoolCount++;
				}
				break; // break switch
			} // end of NEED_UNWRAP
			case NEED_WRAP: {
				// The engine wants to give us data to send to the remote party to advance
				// the handshake. Let it :-)

				if (sessionMetadata.outNetBuffer == null) {
					sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
					getPoolCount++;
				}
				ByteBuffer outNetBuffer = sessionMetadata.outNetBuffer;
				if (outNetBuffer.position() == 0) {
					// We have no outstanding data to write for the handshake (from a previous wrap())
					// so ask the engine for more.
					/*result = */engine.wrap(BLANK, outNetBuffer);
					processCount++;
					outNetBuffer.flip();
				} // else There's data remaining from the last wrap() call, fall through and try to write it

				// Write the data away
				int numWritten = socketChannel.write(outNetBuffer);
				processCount++;
				if (numWritten < 0) {
					throw new SSLException("Handshake aborted by remote entity (socket closed)");
				}
				writeBytes += numWritten;
				
				if (outNetBuffer.hasRemaining()) {
					outNetBuffer.compact();
					key.interestOps(SelectionKey.OP_WRITE);
					return false;
				}

				// All the data was written away, clear the buffer out
				//outNetBuffer.clear();
				if (sessionMetadata.outNetBuffer == outNetBuffer) {
					sessionMetadata.outNetBuffer = null;
				}
				ByteBufferPool.putByteBufferToPool(outNetBuffer);
				putPoolCount++;
				
				if (engine.getHandshakeStatus() == HandshakeStatus.NEED_UNWRAP) {
					// We need more data (to pass to unwrap(), signal we're interested
					// in reading on the socket
					key.interestOps(SelectionKey.OP_READ);
					// And return since we have to wait for the socket to become available.
					return false;
				}
				
				// For all other cases fall through so we can check what the next step is.
				// This ensures we handle delegated tasks, and handshake completion neatly.
				break;
			} // end of branch NEED_WRAP
			} // end of switch
		}
	}
	
	private void delegateSSLEngineTasks(SocketChannel socket, SSLEngine engine) {
		Runnable task;
		while ((task = engine.getDelegatedTask()) != null) {
			// TODO: We could use a thread pool and hand these out. Later.
			exec.execute(task);
		}
		processCount++;
	}

	void writeSSLDummyPacket(NioConnector sessionMetadata, SocketChannel socketChannel) {
		if (sessionMetadata.outNetBuffer == null) {
			sessionMetadata.outNetBuffer = ByteBufferPool.getByteBufferFromPool(sessionMetadata.bufferSize);
			getPoolCount++;
		}
		ByteBuffer outNetBuffer = sessionMetadata.outNetBuffer;
		try {
			/*SSLEngineResult res = */sessionMetadata.engine.wrap(BLANK, outNetBuffer);
			outNetBuffer.flip();
			socketChannel.write(outNetBuffer);
		} catch (Throwable e) {
			// Problems with the engine. Probably it is dead. So close 
			// the socket and forget about it. 
			if (socketChannel != null) {
				try {
					socketChannel.close();
				} catch (IOException ex) {
					/* Ignore. */
				}
			}
		}
		if (sessionMetadata.outNetBuffer == outNetBuffer) {
			sessionMetadata.outNetBuffer = null;
		}
		ByteBufferPool.putByteBufferToPool(outNetBuffer);
		putPoolCount++;
	}
	
}
