package net.zenconsult.forensics;

import java.util.TimeZone;

public class StatusRecord extends ConRecord{

	public StatusRecord(byte[] data) {
		super(0x30, data);		
	}

}
