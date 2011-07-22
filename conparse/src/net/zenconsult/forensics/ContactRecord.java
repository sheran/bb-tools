package net.zenconsult.forensics;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Vector;

public class ContactRecord extends ConRecord{
	private Vector unknownRecs = new Vector();
	private String contactName;
	private String contactPIN;
	private String status;
	private String oldPin;
	private String barcode;
	private String customName;
	
	public ContactRecord(byte[] data) {
		super(0x05, data);
		
		int count = 0;
		DataInputStream ds = new DataInputStream(new ByteArrayInputStream(data));
		try {
			while(true){
				int rSize = ds.readShort();
				count +=2;
				int rType = ds.read();
				count++;
				byte[] rDat = new byte[rSize];
				ds.read(rDat);
				count +=rSize;
				switch(rType){
					case 0x02: {
						contactName = new String(rDat);
						break;
					}
					
					case 0x01: { 
						contactPIN = new String(rDat);
						break;
					}
					
					case 0x30: {
						setStatus(new String(rDat));
						break;
					}
					
					case 0x15: {
						setOldPin(new String(rDat));
					}
					
					case 0x06: {
						setBarcode(new String(rDat));
						break;
					}
					
					case 0x03: {
						customName = new String(rDat);
						break;
					}
					
					
					default:{
						unknownRecs.add(new ConRecord(rType,rDat));
						break;
					}
				
				}
				if(count == getSize())
					break;
				
				
			}
			
			
		} catch(IOException e){
			
		}
		
		try {
			ds.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	
	}
	
	public Vector getUnknown(){
		return unknownRecs;
	}
	
	public String getContactName(){
		return contactName;
	}
	
	public String getContactPIN(){
		return contactPIN;
	}
	
	public String getCustomName(){
		return customName;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getStatus() {
		return status;
	}

	public void setOldPin(String oldPin) {
		this.oldPin = oldPin;
	}

	public String getOldPin() {
		return oldPin;
	}

	public void setBarcode(String barcode) {
		this.barcode = barcode;
	}

	public String getBarcode() {
		return barcode;
	}

}
