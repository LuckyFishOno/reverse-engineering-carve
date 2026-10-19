package carve.reference;

import java.io.*;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

/** Reviewed projection adapter. Calls the original shipped loadZipBytes/getZip JNI;
 * no installer/native implementation or precomputed archive catalog is compiled here.
 * The selected result is ZIP central-directory metadata, filtered/paged by the adapter.
 */
public final class TermuxBootstrapHarness {
    private static Class<?> objectClass;
    private static Object field(Object object, String key, Object fallback) throws Exception {
        if (!(Boolean)objectClass.getMethod("has",String.class).invoke(object,key)) return fallback;
        return objectClass.getMethod("get",String.class).invoke(object,key);
    }
    private static String quote(String text) throws Exception {
        return (String)objectClass.getMethod("quote",String.class).invoke(null,text);
    }
    private static int integer(Object value, int min, int max) {
        if (!(value instanceof Number)) throw new IllegalArgumentException("Expected integer");
        double n=((Number)value).doubleValue();
        if (!Double.isFinite(n)||n!=Math.floor(n)||n<min||n>max) throw new IllegalArgumentException("Out of domain");
        return (int)n;
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=0)throw new IllegalArgumentException("JSON stdin required");
        ByteArrayOutputStream input=new ByteArrayOutputStream(); byte[] buffer=new byte[8192];int n;
        while((n=System.in.read(buffer))!=-1){if(input.size()+n>1048576)throw new IllegalArgumentException("Input limit");input.write(buffer,0,n);}
        objectClass=Class.forName("org.json.JSONObject");Class<?> arrays=Class.forName("org.json.JSONArray");
        Object positional=arrays.getConstructor(String.class).newInstance(new String(input.toByteArray(),"UTF-8"));
        if((Integer)arrays.getMethod("length").invoke(positional)!=1)throw new IllegalArgumentException("One query required");
        Object query=arrays.getMethod("getJSONObject",int.class).invoke(positional,0);
        Iterator<?> keys=(Iterator<?>)objectClass.getMethod("keys").invoke(query);
        while(keys.hasNext()){Object k=keys.next();if(!Arrays.asList("prefix","offset","limit").contains(k))throw new IllegalArgumentException("Unknown query field");}
        Object prefixValue=field(query,"prefix","");if(!(prefixValue instanceof String))throw new IllegalArgumentException("Prefix must be text");
        String prefix=(String)prefixValue;if(prefix.length()>256)throw new IllegalArgumentException("Prefix limit");
        int offset=integer(field(query,"offset",0),0,1000000),limit=integer(field(query,"limit",20),1,100);
        Class<?> installer=Class.forName("com.termux.app.TermuxInstaller");
        Method original=installer.getDeclaredMethod("loadZipBytes");original.setAccessible(true);
        byte[] bytes=(byte[])original.invoke(null);
        StringBuilder hash=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))hash.append(String.format(Locale.ROOT,"%02x",b&255));
        // A fresh file in this reference session's private remote directory; never the app's files.
        File parent=new File(System.getProperty("java.class.path").split(":")[0]).getParentFile();
        File archive=File.createTempFile("bootstrap-",".zip",parent);
        List<String> items=new ArrayList<>();int total=0,matched=0;
        try {
            try(FileOutputStream output=new FileOutputStream(archive)){output.write(bytes);}
            try(ZipFile zip=new ZipFile(archive)){
                Enumeration<? extends ZipEntry> entries=zip.entries();
                while(entries.hasMoreElements()){
                    ZipEntry e=entries.nextElement();total++;
                    if(!e.getName().startsWith(prefix))continue;
                    int current=matched++;
                    if(current<offset||items.size()>=limit)continue;
                    items.add("{\"name\":"+quote(e.getName())+",\"bytes\":"+e.getSize()+",\"compressedBytes\":"+e.getCompressedSize()+",\"crc32\":"+e.getCrc()+",\"directory\":"+e.isDirectory()+"}");
                }
            }
        } finally {if(!archive.delete())throw new IOException("Private derived ZIP cleanup failed");}
        int next=offset+items.size();
        System.out.println("{\"archiveBytes\":"+bytes.length+",\"archiveSha256\":"+quote(hash.toString())+",\"totalEntries\":"+total+",\"matchedEntries\":"+matched+",\"items\":["+String.join(",",items)+"],\"nextOffset\":"+(next<matched?Integer.toString(next):"null")+"}");
    }
}
