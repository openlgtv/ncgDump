package com.smx.ncgdump;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 *
 * @author sm
 */
public class NCGDecoder {
	private static final String xorData = 
			"080d0e0f040001090e0b0f010d050a0505030f0209060d020b0d0503" +
			"0d09060b0a0f080c02050801000a0102060c050106060e060b0501050201" +
			"010509030b0d0f03020b0e050807040e0c0d09010c0c0a060f0309000f07" +
			"090802020e0905080e0b060200020f050d0e0108050f030f050f0c080501" +
			"020101080e0e0000000e090b04070a050507030d0503010602070c0b0300" +
			"04050a0e010806010a07010d090f000a060b0b060707030f0500060f080c" +
			"05070909010b08020a000a040c08020306070a07000c0b0100050c080403" +
			"0d0a020e0d0603010e030a080f0b090008040d050601080c0d090709060f" +
			"000c03080c0f040f0409090902010a0f0b0b0a070901030c07020f020007" +
			"0d000a0207050f0501030b040b00060b06090a0002030a0c0d09010c0907" +
			"0f05050f0e080f060e050c020404080d0d0e0c040f020903020c0a030306" +
			"06090e09060e0d0d0c02020c0e0f0103010d0402070904060b0c0c0b050c" +
			"030f0c0e0b0407070105000d010509050d0e0907060c030408000f0a0b09" +
			"080f010b00010f05000200060103040b090404090f090a0900050503040f" +
			"090308050a09040c0b08060e0b0a090c0f07090e0a0d010407020f0b0b0e" +
			"0008030c03010a0a000a080f0205000f0d0e050405080409000701000207" +
			"0a04070f0102050b03070e020f0f0f03070300020d050e090f0909080e07" +
			"080a0101";
		
	private static final byte[] INDICES_DATA;
	
	static {
		try {
			INDICES_DATA = Hex.decodeHex(xorData);
		} catch (DecoderException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	private NCGFile file;
	private byte[] aes_key;
	private byte[] aes_iv;
	
	private int seed;
	
	public NCGDecoder(NCGFile file, byte[] aes_key, byte[] aes_iv){
		this.file = file;
		this.aes_key = aes_key;
		this.aes_iv = aes_iv;
		computeSeed();
	}
	
	private void computeSeed(){
		seed = 0;
		String cid = file.getDescriptor().getCidString();
		for(int i=0; i<cid.length(); i++)
			seed += cid.charAt(i);
		
		seed %= 16;
	}
	
	private void decryptBlock(byte[] blockData){
		ByteBuffer offsets = ByteBuffer.wrap(INDICES_DATA);
		
		if(blockData.length == 512){
			// get offsets from table
			offsets = offsets.position(32 * seed).slice();
			
			// populate keys
			byte keys[] = new byte[32];
			for(int i=0, offset=0; i<keys.length; i++, offset += 16){
				byte tblByte = offsets.get();
				keys[i] = blockData[offset + tblByte];
			}
			
			// xor data with keys
			for(int i=0; i<480;){
				for(byte k : keys){
					blockData[i++] ^= k;
				}
			}
			
			// decrypt keys
			keys = Crypto.aesDecrypt(keys, aes_key, aes_iv);
			
			// repeat with decrypted offsets
			offsets.rewind();
			for(int i=0, offset=0; i<keys.length; i++, offset += 16){
				byte index = offsets.get();
				blockData[offset + index] = keys[i];
			}
		} else {
			byte[] decrypted = Crypto.aesDecrypt(blockData, aes_key, aes_iv);
			System.arraycopy(decrypted, 0, blockData, 0, decrypted.length);
		}
	}
	
	public byte[] getContents() throws IOException {	
		int data_pos = 512 + file.getHeader().getBodySize();
		ByteBuffer buf = file.getBuffer().position(data_pos).slice();
		int length = buf.remaining();
		
		int last_offset = 0;
		int last_size = 0;
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
		
		if(length >= 512){
			for(int offset=0; offset < length && length - offset >= 512; offset += 512){
				byte block[] = new byte[512];
				buf.get(block);
				
				decryptBlock(block);
				baos.write(block);
			}
			
			int remaining = length - 512;
			last_offset = ((remaining >> 9) + 1) << 9;
			length = remaining & 0x1FF;
		}
		
		if(length > 0){
			byte[] block = new byte[length];
			buf.position(last_offset).get(block);
			decryptBlock(block);
			baos.write(block);
		}
		
		byte[] decrypted = baos.toByteArray();
		System.out.println(new String(decrypted, StandardCharsets.US_ASCII));
		
		return decrypted;
	}
}
