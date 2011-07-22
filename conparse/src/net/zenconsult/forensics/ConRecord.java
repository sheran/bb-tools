package net.zenconsult.forensics;

public class ConRecord {
	private int recSize;
	private int recType;
	private byte[] recData;
	
	public ConRecord(int type, byte[] data){
		recType = type;
		recData = data;
		recSize = recData.length;
	}
	
	public int getType(){
		return recType;
	}
	
	public byte[] getRawData(){
		return recData;
	}
	
	public String getDataAsString(){
		return new String(recData);
	}
	
	public String getPrintableString() {
		StringBuffer buf = new StringBuffer();
		for(int k = 0; k < recData.length;++k){
			if(recData[k] > 0x20 && recData[k] < 0x7F){
				buf.append((char)recData[k]);
			} else {
				buf.append(".");
			}
		}
		return buf.toString();
	}
	
	public int getSize(){
		return recSize;
	}
	
}
