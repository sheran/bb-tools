package net.zenconsult.forensics;

import java.util.HashMap;

public class ImageMimeTypes {
	private static HashMap<String, String> imageTypeMapping = new HashMap<String, String>(){{
		put("image/bmp","bmp");
		put("image/cis-cod","cod");
		put("image/gif","gif");
		put("image/ief","ief");
		put("image/jpeg","jpe");
		put("image/jpeg","jpeg");
		put("image/jpeg","jpg");
		put("image/pipeg","jfif");
		put("image/png","png");
		put("image/svg+xml","svg");
		put("image/tiff","tif");
		put("image/tiff","tiff");
		put("image/x-cmu-raster","ras");
		put("image/x-cmx","cmx");
		put("image/x-icon","ico");
		put("image/x-portable-anymap","pnm");
		put("image/x-portable-bitmap","pbm");
		put("image/x-portable-graymap","pgm");
		put("image/x-portable-pixmap","ppm");
		put("image/x-rgb","rgb");
		put("image/x-xbitmap","xbm");
		put("image/x-xpixmap","xpm");
		put("image/x-xwindowdump","xwd");
	}};
	
	public static String getExtenstion(String mimetype){
		if(imageTypeMapping.containsKey(mimetype))
			return imageTypeMapping.get(mimetype);
		else
			return("dat");
	}
	
}
