package net.zenconsult.forensics;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Vector;

public class ContactsRecord extends ConRecord{
	private ContactGroupRecord conGroup;
	private Vector contactGroups;

	public ContactsRecord(byte[] data) {
		super(0x02, data);
		
		contactGroups = new Vector();
		DataInputStream ds = new DataInputStream(new ByteArrayInputStream(data));
		int count = 0;
		try {
			while(true){
				int rSize = ds.readShort();
				count +=2;
				int rType = ds.read();
				count++;
				byte[] rDat = new byte[rSize];
				ds.read(rDat);
				count +=rSize;
				if(rType == 0x06){
					conGroup = new ContactGroupRecord(rDat);
					contactGroups.add(conGroup);
				}
				if(count == getSize())
					 break;
			}
			
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			ds.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
	
	public Vector getContactGroups(){
		return contactGroups;
	}
	
	
	
	

}
