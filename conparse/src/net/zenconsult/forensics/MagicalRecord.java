package net.zenconsult.forensics;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Vector;

public class MagicalRecord extends ConRecord{
	private TimeZoneRecord tzRecord;
	private ImageRecord imgFile;
	private StatusRecord status;
	private CountryFlagRecord countryFlag;
	private UnknownRecord type0x04;
	private ImageTypeRecord imgType;
	private UnknownRecord type0x1d;
	private UnknownRecord type0x1e;

	public MagicalRecord(byte[] data) {
		super(0x14, data);
		
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
				switch(rType){
				case 0x35: tzRecord = new TimeZoneRecord(rDat); break;
				case 0x1F: imgFile = new ImageRecord(rDat); break;
				case 0x30: status = new StatusRecord(rDat); break;
				case 0x31: countryFlag = new CountryFlagRecord(rDat); break;
				case 0x04: type0x04 = new UnknownRecord(rType, rDat); break;
				case 0x1C: imgType = new ImageTypeRecord(rDat); break;
				case 0x1D: type0x1d = new UnknownRecord(rType, rDat); break;
				case 0x1E: type0x1e = new UnknownRecord(rType, rDat); break;
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
	
	public TimeZoneRecord getTzRecord() {
		return tzRecord;
	}

	public void setTzRecord(TimeZoneRecord tzRecord) {
		this.tzRecord = tzRecord;
	}

	public ImageRecord getImgFile() {
		return imgFile;
	}

	public void setImgFile(ImageRecord imgFile) {
		this.imgFile = imgFile;
	}

	public StatusRecord getStatus() {
		return status;
	}

	public void setStatus(StatusRecord status) {
		this.status = status;
	}

	public CountryFlagRecord getCountryFlag() {
		return countryFlag;
	}

	public void setCountryFlag(CountryFlagRecord countryFlag) {
		this.countryFlag = countryFlag;
	}

	public UnknownRecord getType0x04() {
		return type0x04;
	}

	public void setType0x04(UnknownRecord type0x04) {
		this.type0x04 = type0x04;
	}

	public ImageTypeRecord getImgType() {
		return imgType;
	}

	public void setImgType(ImageTypeRecord imgType) {
		this.imgType = imgType;
	}

	public UnknownRecord getType0x1d() {
		return type0x1d;
	}

	public void setType0x1d(UnknownRecord type0x1d) {
		this.type0x1d = type0x1d;
	}

	public UnknownRecord getType0x1e() {
		return type0x1e;
	}

	public void setType0x1e(UnknownRecord type0x1e) {
		this.type0x1e = type0x1e;
	}
	
	

}
