package net.zenconsult.forensics;

import java.util.TimeZone;

public class TimeZoneRecord extends ConRecord{

	public TimeZoneRecord(byte[] data) {
		super(0x35, data);		
	}
	
	public TimeZone getTimeZone(){
		return TimeZone.getTimeZone(getDataAsString()); 
	}

}
