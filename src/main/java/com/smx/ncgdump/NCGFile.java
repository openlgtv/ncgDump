package com.smx.ncgdump;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author sm
 */
public class NCGFile {
	public static final int HEADER_SIZE = 512;
	
	private static MappedByteBuffer mmapReadOnly(File file) throws IOException {
		return (MappedByteBuffer)new RandomAccessFile(file.getPath(), "r")
				.getChannel()
				.map(FileChannel.MapMode.READ_ONLY, 0, file.length())
				.order(ByteOrder.LITTLE_ENDIAN);
	}
	
	private ByteBuffer buf;

	public ByteBuffer getBuffer() {
		return buf.duplicate().rewind();
	}
	
	private final NCGHeader header;
	private final NCGDescriptor descr;

	public NCGHeader getHeader() {
		return header;
	}
	
	public NCGDescriptor getDescriptor(){
		return descr;
	}
	
	private NCGFile(Path path){
		File ncgFile = path.toFile();
		try {
			buf = mmapReadOnly(ncgFile);
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		
		header = NCGHeader.parse(buf);
		descr = NCGDescriptor.parse(this);
		
		try {
			// sample keys!
			byte[] aes_key = Hex.decodeHex("93eadc96da53793d8506e2c7b6aa48b2");
			byte[] aes_iv = Hex.decodeHex("288da67bac65ce383cb86289e4b84f77");
			new NCGDecoder(this, aes_key, aes_iv).getContents();
		} catch(Exception ex){
			throw new RuntimeException(ex);
		}
	}
	
	public static NCGFile open(String path){
		return new NCGFile(Paths.get(path));
	}
}
