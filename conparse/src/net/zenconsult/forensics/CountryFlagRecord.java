package net.zenconsult.forensics;

import java.util.TimeZone;

public class CountryFlagRecord extends ConRecord{

	public CountryFlagRecord(byte[] data) {
		super(0x31, data);		
	}

}
