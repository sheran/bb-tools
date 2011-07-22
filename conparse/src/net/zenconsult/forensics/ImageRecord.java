package net.zenconsult.forensics;

import java.util.TimeZone;

public class ImageRecord extends ConRecord{

	public ImageRecord(byte[] data) {
		super(0x1F, data);		
	}

}
