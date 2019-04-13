package com.smx.ncgdump;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.codec.binary.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * @author sm
 */
public class NCGDescriptor {
	private ByteBuffer buf;
	private int maxSize;
	
	private byte[] sid;
	private byte[] cid;
	private String cidString;
	private String packDate;

	public byte[] getSid() {
		return sid;
	}
	
	public String getCidString() {
		return cidString;
	}
	
	public byte[] getCid() {
		return cid;
	}

	public String getPackDate() {
		return packDate;
	}
	
	private NCGDescriptor(ByteBuffer buf, int maxSize){
		this.buf = buf;
		this.maxSize = maxSize;
		
		try {
			parse();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	private void parse() throws Exception {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		
		StringBuilder sb = new StringBuilder();
		for(int i=0; i<maxSize; i++){
			byte ch = buf.get();
			if(ch == 0x00)
				break;
			sb.append((char)ch);
		}
	
		String xml = sb.toString();
	
		InputStream is = new ByteArrayInputStream(xml.getBytes(StandardCharsets.US_ASCII));
		Document doc = dBuilder.parse(is);
		
		Element rootNode = (Element) doc.getFirstChild();
		if(!rootNode.getNodeName().equals("ncgxmlhdr")){
			throw new RuntimeException("Unexpected root tag " + rootNode.getNodeName());
		}
	
		Element content = (Element) rootNode.getElementsByTagName("content").item(0);
		
		String source = content.getElementsByTagName("source").item(0).getTextContent();
		String sid = content.getElementsByTagName("sid").item(0).getTextContent();
		String cid = content.getElementsByTagName("cid").item(0).getTextContent();
		
		this.sid = Hex.decodeHex(sid);
		this.cidString = cid;
		this.cid = Hex.decodeHex(cid);
		
		Node encryptionNode = content.getElementsByTagName("encryption").item(0);
		String encryption_range = encryptionNode.getAttributes().getNamedItem("range").getTextContent();
		String encryption = encryptionNode.getTextContent();
		
		String packDate = content.getElementsByTagName("packdate").item(0).getTextContent();
		
		this.packDate = packDate;
	}
	
	public static NCGDescriptor parse(NCGFile file){
		short size = file.getHeader().getBodySize();
		ByteBuffer buf = file.getBuffer().position(size);
		return new NCGDescriptor(buf, size);
	}
}
