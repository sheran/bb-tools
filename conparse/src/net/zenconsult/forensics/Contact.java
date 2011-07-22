package net.zenconsult.forensics;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public class Contact 
{
	private Hashtable contactDetails;
	private Vector contacts;
	
	public Contact(byte[] data)
	{
		contacts = new Vector();
		DataInputStream bais = new DataInputStream(new ByteArrayInputStream(data));
		for(;;)
		{
			try
			{
				int rSize = (int)bais.read();
				int rType = bais.read();
				byte[] rDat = new byte[rSize];
				bais.read(rDat);
				bais.read();
				if(rType == 0x05)
				{
					contactParse(rDat);
					contacts.add(contactDetails);
				}
				
			} catch(IOException e)
			{
				break;
			}
		}
		
		
		
	}
	
	
	private void contactParse(byte[] rData)
	{
		contactDetails = new Hashtable();
		DataInputStream ds = new DataInputStream(new ByteArrayInputStream(rData));
		for(;;)
		{
			try
			{
				
				short rs = ds.readShort();
				int rt = ds.read();
				byte[] rd = new byte[rs];
				ds.read(rd);
				switch(rt)
				{
				case 0x02: contactDetails.put("Name", getStringData(rd));break;
				case 0x30: contactDetails.put("Status", getStringData(rd));break;
				case 0x01: contactDetails.put("PIN", getStringData(rd));break;
				case 0x09: contactDetails.put("Email", getStringData(rd));break;
				/*case 0x02: System.out.println(getStringData(rd));break;
				case 0x30: System.out.println(getStringData(rd));break;
				case 0x01: System.out.println(getStringData(rd));break;*/
				}
				
			} 
			catch(IOException e)
			{
				break;
			}
			
		}
	}
	
	private String getStringData(byte[] recData)
	{
		StringBuffer j = new StringBuffer();
		for(int s=0;s<recData.length;++s)
		{
			if(recData[s] > 0x7F || recData[s] < 0x20)
			{
				j.append(".");
			} else
			{
				j.append((char)recData[s]);
			}
		}
		return j.toString();
	}
	
	
	public Vector getContacts()
	{
		return contacts;
	
	}
	// Types
	// 0x30 Status
	// 0x02 Name
	// 0x01 PIN
	// 0x33 Unknown
	// 0x34 Unknown
	// 0x06 HEX
	// 0x04 Unknown
	// 0x11 Unknown
	// 0x12 Unknown
	// 0x16 Unknown
	// 0x1B Unknown
	// 0x01 Database Name
	
}
