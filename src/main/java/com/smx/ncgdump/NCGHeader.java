package com.smx.ncgdump;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author sm
 */
public class NCGHeader {
	private ByteBuffer buf;
	
	private short version;
	private short bodySize;
	private short unk;

	
	public short getVersion() {
		return version;
	}

	public short getBodySize() {
		return bodySize;
	}
	
	private final static String HEADER_KEY = "292bf2291f8b4781950a84f891da07d0";
	private final static String HEADER_IV  = "9cde323e9e464afca4cc556ef28161db";

	private void verifyHeader() throws Exception {
		buf.rewind();
		byte[] headerData = new byte[492];
		buf.get(headerData);

		byte[] expectedDigest = new byte[20];
		buf.get(expectedDigest);
		
		byte[] bodyData = new byte[bodySize];
		buf.get(bodyData);
		
		MessageDigest md = Crypto.getSha1();
		md.update(headerData);
		md.update(bodyData);
		byte[] digest = md.digest();
		
		System.out.println("> Digest      : " + Hex.encodeHexString(digest).toUpperCase());
		digest = Crypto.aesDecrypt(
				digest,
				Hex.decodeHex(HEADER_KEY),
				Hex.decodeHex(HEADER_IV));
				
		System.out.println("> Digest-AES  : " + Hex.encodeHexString(digest).toUpperCase());
		System.out.println("> Expected    : " + Hex.encodeHexString(expectedDigest).toUpperCase());
		
		if(!Arrays.equals(digest, expectedDigest)){
			throw new RuntimeException("Digest check failed");
		}
	}
	
	private NCGHeader(ByteBuffer buf){
		this.buf = buf;
		
		byte[] magic = new byte[14];
		buf.get(magic);

		String magicStr = new String(magic, StandardCharsets.US_ASCII);
		if(!magicStr.equals("NCGFILE_HEADER")){
			throw new RuntimeException("Invalid magic " + magicStr);
		}

		version = buf.getShort();
		bodySize = buf.getShort();
		unk = buf.getShort();
		
		try {
			verifyHeader();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public static NCGHeader parse(ByteBuffer buf){
		return new NCGHeader(buf);
	}
}
