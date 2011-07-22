package net.zenconsult.forensics;

public class Record 
{

	private int skip;
	private String recType;
	private byte[] recData;

	public Record(int dType, byte[] data)
	{
		skip = 0;
		recData = data;
		identify(dType);
	}
	
	private void identify(int type)
	{
		recType = new String();
		switch(type)
		{
		case 0x35: recType="Timezone"; break;
		case 0x0A: recType="Own PIN"; break;
		case 0x01: recType="Contact PIN"; break;
		case 0x04: recType="Record Type 0x04"; break;
		case 0x06: recType="Contact Group"; break;
		case 0x30: recType="Status"; break;
		case 0x02: recType="Contact Name";break;
		case 0x03: recType="Own Name"; break;
		case 0x1C: recType="Image Type"; break;
		case 0x1F: recType="Own Image"; break;
		case 0x05: recType="Contact Record"; break;
		case 0x07: recType="Record Type 0x07"; break;
		case 0x18: recType="Base64 Record";break;
		default: recType="Record Type "+type; break;
		}
		
	}
	
	public int getSkip()
	{
		return skip;
	}
	
	public String getRecType()
	{
		return recType;
	}
	
	public String getStringData()
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
	
	public byte[] getRawData()
	{
		return recData;
	}
}
