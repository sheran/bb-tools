package net.zenconsult.forensics;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Vector;

public class ContactGroupRecord extends ConRecord {
	private Vector contacts = new Vector();
	private Vector unknownRecs = new Vector();
	
	public ContactGroupRecord(byte[] data) {
		super(0x06, data);
		
		int count = 0;
		DataInputStream ds = new DataInputStream(new ByteArrayInputStream(data));
		while(true){
			try {
				int rSize = ds.readShort();
				count +=2;
				int rType = ds.read();
				count++;
				
				byte[] rDat = new byte[rSize];
				ds.read(rDat);
				count +=rSize;
				
				if(rType == 0x05){
					contacts.add(new ContactRecord(rDat));
					
				} else {
					unknownRecs.add(new ConRecord(rType,rDat));
				}
				if(count == getSize())
					break;
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		try {
			ds.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public Vector getContacts(){
		return contacts;
	}

}
