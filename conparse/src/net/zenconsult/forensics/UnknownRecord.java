package net.zenconsult.forensics;

import java.util.TimeZone;

public class UnknownRecord extends ConRecord{

	public UnknownRecord(int rtype, byte[] data) {
		super(rtype, data);		
	}

}
