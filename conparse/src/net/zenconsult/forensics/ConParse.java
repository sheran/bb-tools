/* 
# ConParse v1.0 - Parser for BlackBerry Messenger .con (contact) files
# Copyright (C) 2011, Sheran A. Gunasekera <sheran@zensay.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
*/

package net.zenconsult.forensics;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Vector;
import java.util.Date;

public class ConParse 
{
	private static String verNum = "ConParse v1.0 - Copyright (C) 2011, Sheran A. Gunasekera <sheran@zensay.com>";
	
	public static void main(String[] args)
	{
		if(args.length > 2 || args.length == 0)
		{
			usage();
			System.exit(0);
		}
		
		Vector records = new Vector();
		String filename = args[0];
		File conFile = new File(filename);
		try 
		{
			DataInputStream ds = new DataInputStream(new FileInputStream(conFile));
			int offset = 0;
			byte firstCheck = ds.readByte();
			offset++;
			ds.skipBytes(32);
			offset += 32;
			short secondCheck = ds.readShort();
			offset +=2;
			if(firstCheck != 0x20 && secondCheck != 0x7f80)
			{
				System.out.println("not a con file");
				System.exit(0);
			}
			System.out.println(verNum);
			System.out.println("Parsing: "+filename);
			short unknownPad = ds.readShort();
			offset +=2;
			short fileSize = ds.readShort();
			offset +=2;
			int readSoFar = offset;
			while(true){
				try {
					int rSize = ds.readShort();
					offset +=2;
					int rType = ds.read();
					offset++;
					byte[] rData = new byte[rSize];
					ds.read(rData);
					offset +=rSize;
					records.add(new ConRecord(rType,rData));
				} catch(EOFException e) {
					break;
				}
				
			}
			String rptFilename = "ConParse_report_"+new Date().getTime()+".html";
			FileOutputStream reportFile = new FileOutputStream(new File(rptFilename));
			
			String hdr = "<html>\n<head>\n<title>ConParse Report\n</title>\n</head><body>\n";
			reportFile.write(hdr.getBytes());
			
			String hdr1 = "<center><h4>"+verNum+"</h4></center>\n<hr>\n";
			reportFile.write(hdr1.getBytes());
			
			
			
			for(int k=0; k< records.size();++k){
				ConRecord d = (ConRecord)records.get(k);
				
				if(d.getType() == 0x14) {
					MagicalRecord magic = new MagicalRecord(d.getRawData());
					
					if(magic.getImgType() != null){
						String mimeType = magic.getImgType().getDataAsString();
						String extension = ImageMimeTypes.getExtenstion(mimeType);
						String imgFileName = "profile_picture_"+new Date().getTime()+"."+extension;
						FileOutputStream fos = new FileOutputStream(new File(imgFileName));
						fos.write(magic.getImgFile().getRawData());
						fos.close();
						String dtls = "<h3>Picture & Status</h3>\n<table border=1>\n<tr><td>Profile Picture</td><td><img src=\""+imgFileName+"\" /></td></tr></table>\n";
						reportFile.write(dtls.getBytes());
					}
					
					String dtls1 = "<table><tr><td><b>Status:</b></td><td>"+magic.getStatus().getDataAsString()+"</td></tr>\n";
					dtls1 = dtls1.concat("<tr><td><b>Flag Pic:</b></td><td>"+magic.getCountryFlag().getDataAsString()+"</td></tr>\n");
					dtls1 = dtls1.concat("<tr><td><b>TimeZone:</b</td><td>"+magic.getTzRecord().getDataAsString()+"</td></tr>\n</table>");
					reportFile.write(dtls1.getBytes());
				
				}
				
				if(d.getType() == 0x03) {
					String dtls2 = "<table><tr><td><b>Name:</b></td><td>"+d.getDataAsString()+"</td></tr></table>\n";
					reportFile.write(dtls2.getBytes());
				}
				
				if(d.getType() == 0x0A) {
					String dtls2 = "<table><tr><td><b>PIN:</b></td><td>"+d.getDataAsString()+"</td></tr></table>\n";
					reportFile.write(dtls2.getBytes());
				}
				
				if(d.getType() == 0x18) {
					String dtls2 = "<table><tr><td><b>Barcode B64:</b></td><td>"+d.getDataAsString()+"</td></tr></table>\n";
					reportFile.write(dtls2.getBytes());
				}
				
				if(d.getType() == 0x04) {
					String dtls2 = "<table><tr><td><b>Hex Value:</b></td><td>"+d.getDataAsString()+"</td></tr></table>\n";
					reportFile.write(dtls2.getBytes());
				}
				
				if(d.getType() == 0x45) {
					String dtls2 = "<table><tr><td><b>Magic #:</b></td><td>"+d.getDataAsString()+"</td></tr></table>\n";
					reportFile.write(dtls2.getBytes());
				}
				
				if(d.getType() == 0x02) {
					int contactCount = 0;
					String contactRpt = "<h3>Contacts</h3>\n<table border=1>\n<tr><td><b>Name</b></td><td><b>PIN</b></td><td><b>Status</b></td><td><b>Custom Name</b></td><td><b>Hex Value</b></td></tr>\n";
					reportFile.write(contactRpt.getBytes());
					
					ContactsRecord c = new ContactsRecord(d.getRawData());
					Vector cGroups = c.getContactGroups();
					for(int cg=0; cg < cGroups.size(); ++cg){
						ContactGroupRecord r = (ContactGroupRecord)cGroups.get(cg);
						Vector contacts = r.getContacts();
						for(int a=0; a<contacts.size();++a){
							ContactRecord cr = (ContactRecord)contacts.get(a);
							String contactRpt1 = "<tr><td>"+cr.getContactName()+"</td><td>"+cr.getContactPIN()+"</td><td>"+cr.getStatus()+"</td><td>"+cr.getCustomName()+"</td><td>"+cr.getBarcode()+"</td></tr>\n";
							reportFile.write(contactRpt1.getBytes());
							contactCount++;
						}
					}
					reportFile.write(("<tr><td><b>Total Contacts:</b></td><td colspan=4><center><b>"+contactCount+"</b></center></td></tr>\n").getBytes());
					reportFile.write("</table>\n".getBytes());
					
				}
			}
			reportFile.write("</body>\n</html>\n".getBytes());
			reportFile.close();
			ds.close();
		} 
		catch (FileNotFoundException e) 
		{
			System.out.println("File Not Found");
		} catch (IOException e)
		{
			e.printStackTrace();
		} 
	}

	public static void usage()
	{
		System.out.println(verNum);
		System.out.println("Usage: ConParse <CON or BAK file>");
	}
	
}
