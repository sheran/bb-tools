/* 
# Evt2Sqlite v0.1b - Convert BlackBerry Event Log files to SQLite databases
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Evt2Sqlite {
	public static void main(String[] args){
		if(args.length < 2 || args.length > 2){
			usage();
			System.exit(0);
		}
		String dbFilename = args[1];
		String drStmt = "DROP TABLE IF EXISTS EVENT;";
		String crStmt = "CREATE TABLE EVENT (GUID STRING, EVDATE DATE, TYPE INTEGER, SEVERITY INTEGER, APP STRING, DATA STRING);";
		String filename = args[0];
		BufferedReader reader = null;
		String tmpLine = "";
		int lineCount = -1;
		Pattern p = Pattern.compile("^guid:(.*).*time:(.*).*severity:(.*).*type:(.*).*app:(.*).*data(:|.*)",Pattern.MULTILINE|Pattern.DOTALL);
		Matcher m = null;
		Connection con = null;
		Statement stat = null;
		PreparedStatement ps = null;
		try {
			Class.forName("org.sqlite.JDBC");
			con = DriverManager.getConnection("jdbc:sqlite:"+dbFilename);
			stat = con.createStatement();
			stat.executeUpdate(drStmt);
			stat.executeUpdate(crStmt);
			stat.close();
			
			
		} catch (SQLException e1) {
			System.out.println("SQL Exception");
		} catch (ClassNotFoundException e) {
			System.out.println("Class not found org.sqlite.JDBC");
		}
		
	
		try {
			reader = new BufferedReader(new FileReader(new File(filename)));
		} catch (FileNotFoundException e) {
			System.out.println("File not found");
		}
		
		String brokenLine = "";
		String tmpData = "";
		Matcher tmpMatcher = null;
		boolean matched = false;
		SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy");
		try {
			ps = con.prepareStatement("INSERT INTO EVENT VALUES(?,?,?,?,?,?);");
			con.setAutoCommit(false);
			while( (tmpLine = reader.readLine()) != null){
				lineCount++;
				m = p.matcher(tmpLine);
				
				if(m.matches()) {
					if(!brokenLine.equals("")){
						ps.setString(1, m.group(1).trim());
						long t = sdf.parse((m.group(2)).trim()).getTime();
						t = t / 1000;
						Date dt = new Date(t);
						ps.setDate(2, dt);
						ps.setInt(3, Integer.valueOf(m.group(3).trim()));
						ps.setInt(4, Integer.valueOf(m.group(4).trim()));
						ps.setString(5, m.group(5).trim());
						ps.setString(6, tmpData.substring(1).trim());
						ps.addBatch();
					}
					brokenLine = m.group(6);
					tmpData = brokenLine;
					tmpMatcher = m;
				} 
				else{
					brokenLine += " "+tmpLine;
					tmpData = brokenLine;
					brokenLine = "";
					ps.setString(1, tmpMatcher.group(1).trim());
					long t = sdf.parse((tmpMatcher.group(2)).trim()).getTime();
					t = t / 1000;
					Date dt = new Date(t);
					ps.setDate(2, dt);
					ps.setInt(3, Integer.valueOf(tmpMatcher.group(3).trim()));
					ps.setInt(4, Integer.valueOf(tmpMatcher.group(4).trim()));
					ps.setString(5, tmpMatcher.group(5).trim());
					ps.setString(6, tmpData.substring(1).trim());
					ps.addBatch();
				}
				ps.executeBatch();
				con.commit();
			}
		} catch (IOException e) {
			System.out.println("IO Exception");
		} catch (SQLException e) {
			System.out.println("SQL Exception");
		} catch (ParseException e) {
			System.out.println("Parse Exception");
		}
		
		try {
			con.close();
		} catch (SQLException e1) {
			System.out.println("SQL Exception");
		}
		
		try {
			reader.close();
		} catch (IOException e) {
			System.out.println("Exception closing reader");
		}
		
	}
	
	public static void usage() {
		System.out.println("Usage: java net.zenconsult.forensics.Evt2Sqlite <input file name> <output file name>");
		System.out.println("  The input file:  Only works for BlackBerry Event Log files.");
		System.out.println("  The output file:  Writes an SQLite database");
	}
}
