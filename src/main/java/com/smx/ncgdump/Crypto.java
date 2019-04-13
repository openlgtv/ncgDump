package com.smx.ncgdump;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author sm
 */
public class Crypto {
	public static MessageDigest getSha1(){
		try {
			return MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public static Cipher getAes(){
		try {
			return Cipher.getInstance("AES/CTR/NoPadding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new RuntimeException(ex);
		}
	}
	
	public static byte[] aesDecrypt(byte[] data, byte[] key, byte[] iv) {
		Cipher aes = getAes();
		
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		try {
			aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
			throw new RuntimeException(ex);
		}
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		CipherOutputStream cos = new CipherOutputStream(baos, aes);
		
		try {
			cos.write(data);
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		
		return baos.toByteArray();
	}
	
}
