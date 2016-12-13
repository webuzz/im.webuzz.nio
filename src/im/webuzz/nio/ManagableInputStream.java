package im.webuzz.nio;

import java.io.IOException;
import java.io.InputStream;

public class ManagableInputStream extends InputStream {

	private byte[] buffer;
	private int begin;
	private int end;
	
	public void push(byte[] data, int offset, int length) {
		if (data == null || data.length == 0 || offset < 0 || length < 0 || offset + length > data.length) {
			// considered as error
			return;
		}
		if (buffer == null) {
			buffer = new byte[length];
			System.arraycopy(data, offset, buffer, 0, length);
			end = length;
		} else {
			int currentLength = end - begin;
			if (currentLength + length > buffer.length) {
				byte[] newBuffer = new byte[currentLength + length];
				System.arraycopy(buffer, begin, newBuffer, 0, currentLength);
				System.arraycopy(data, offset, newBuffer, currentLength, length);
				buffer = newBuffer;
			} else {
				if (begin > 0) {
					for (int i = begin; i < end; i++) {
						buffer[i - begin] = buffer[i];
					}
				}
				System.arraycopy(data, offset, buffer, currentLength, length);
			}
			end = currentLength + length;
		}
		begin = 0;
	}
	
	public void push(byte[] data) {
		if (data == null || data.length == 0) {
			return;
		}
		push(data, 0, data.length);
	}
	
	@Override
	public int read() throws IOException {
		if (begin >= end) {
			if (end > 4096) {
				buffer = null;
				begin = 0;
				end = 0;
			}
			return -1; // reach the end of all data
		}
		return buffer[begin++];
	}

	@Override
	public int available() throws IOException {
		int avail = this.end - this.begin;
		if (avail == 0 && end > 4096) {
			buffer = null;
			begin = 0;
			end = 0;
		}
		return avail;
	}
	
	@Override
	public void close() throws IOException {
		this.begin = 0;
		this.end = 0;
		this.buffer = null;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (b == null) {
		    throw new NullPointerException();
		} else if (off < 0 || len < 0 || len > b.length - off) {
		    throw new IndexOutOfBoundsException();
		} else if (len == 0) {
		    return 0;
		}
		if (begin >= end) {
			if (end > 4096) {
				buffer = null;
				begin = 0;
				end = 0;
			}
			return -1; // reach the end of all data
		}
		int currentLength = this.end - this.begin; 
		int toReadLength = len < currentLength ? len : currentLength;
		System.arraycopy(buffer, this.begin, b, off, toReadLength);
		this.begin += toReadLength;
		return toReadLength;
	}

}
