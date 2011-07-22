package net.zenconsult.forensics;

import java.util.TimeZone;

public class ImageTypeRecord extends ConRecord{

	public ImageTypeRecord(byte[] data) {
		super(0x1C, data);		
	}

}
