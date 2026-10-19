// Carve-owned static analysis exporter. Target code is never executed.
// @category Carve
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.framework.Application;
import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class CarveExport extends HeadlessScript {
    private PrintWriter out;
    private void emit(JsonObject value) { out.println(value.toString()); out.flush(); }
    private JsonObject object(String kind) { JsonObject value=new JsonObject();value.addProperty("kind",kind);return value; }
    private JsonObject reference(Reference ref) {
        JsonObject r=new JsonObject();r.addProperty("address",ref.getFromAddress().toString());r.addProperty("targetAddress",ref.getToAddress().toString());r.addProperty("type",ref.getReferenceType().toString());
        Function owner=currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        if(owner!=null){r.addProperty("function",owner.getName(true));r.addProperty("functionAddress",owner.getEntryPoint().toString());r.addProperty("functionExternal",owner.isExternal());r.addProperty("functionThunk",owner.isThunk());}
        Function target=currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
        if(target!=null){r.addProperty("targetFunction",target.getName(true));r.addProperty("targetFunctionAddress",target.getEntryPoint().toString());r.addProperty("targetExternal",target.isExternal());r.addProperty("targetThunk",target.isThunk());}
        return r;
    }
    private JsonObject string(Data item) {
        String text=(String)item.getValue();JsonObject value=object("string");value.addProperty("address",item.getAddress().toString());
        value.addProperty("text",text.length()<=8192?text:text.substring(0,8192));value.addProperty("truncated",text.length()>8192);
        JsonArray refs=new JsonArray();ReferenceIterator references=currentProgram.getReferenceManager().getReferencesTo(item.getAddress());int n=0;
        while(references.hasNext()) {if(n++>=100){value.addProperty("referencesTruncated",true);break;}refs.add(reference(references.next()));}
        value.add("references",refs);return value;
    }
    private JsonObject window(String selector,int requested) throws Exception {
        if(requested<1||requested>4096)throw new IllegalArgumentException("window bytes 1..4096");
        Address start=currentProgram.getAddressFactory().getAddress(selector);if(start==null)throw new IllegalArgumentException("invalid window address");
        MemoryBlock block=currentProgram.getMemory().getBlock(start);if(block==null||!block.isInitialized())throw new IOException("Address is not in initialized program memory");
        int size=(int)Math.min(requested,block.getEnd().subtract(start)+1);byte[] bytes=new byte[size];
        if(currentProgram.getMemory().getBytes(start,bytes)!=size)throw new IOException("Incomplete memory window");
        JsonObject result=object("data-window");result.addProperty("address",start.toString());result.addProperty("requestedBytes",requested);result.addProperty("bytes",size);result.addProperty("truncated",size<requested);result.addProperty("block",block.getName());result.addProperty("executable",block.isExecute());
        StringBuilder hex=new StringBuilder();for(byte b:bytes)hex.append(String.format("%02x",b&255));result.addProperty("hex",hex.toString());
        Address end=start.addNoWrap(size-1);JsonArray references=new JsonArray();int n=0;
        AddressIterator sources=currentProgram.getReferenceManager().getReferenceSourceIterator(new AddressSet(start,end),true);
        outer:while(sources.hasNext()) {monitor.checkCancelled();for(Reference ref:currentProgram.getReferenceManager().getReferencesFrom(sources.next())){if(n++>=512){result.addProperty("referencesTruncated",true);break outer;}references.add(reference(ref));}}
        result.add("references",references);
        JsonArray incoming=new JsonArray();ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(start);n=0;
        while(refs.hasNext()){if(n++>=100){result.addProperty("incomingTruncated",true);break;}incoming.add(reference(refs.next()));}result.add("incomingAtStart",incoming);
        JsonArray pointers=new JsonArray();int pointerSize=currentProgram.getDefaultPointerSize();result.addProperty("pointerSize",pointerSize);result.addProperty("byteOrder",currentProgram.getLanguage().isBigEndian()?"big":"little");
        long initial=pointerSize>0?(pointerSize-Long.remainderUnsigned(start.getOffset(),pointerSize))%pointerSize:0;
        if(pointerSize==4||pointerSize==8)for(long offset=initial;offset+pointerSize<=size;offset+=pointerSize){
            monitor.checkCancelled();Address slot=start.addNoWrap(offset);long raw=pointerSize==8?currentProgram.getMemory().getLong(slot):Integer.toUnsignedLong(currentProgram.getMemory().getInt(slot));
            Address target;
            try{target=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(raw);}catch(Exception ignored){continue;}
            if(currentProgram.getMemory().getBlock(target)==null)continue;
            JsonObject p=new JsonObject();p.addProperty("address",slot.toString());p.addProperty("targetAddress",target.toString());p.addProperty("interpretation","aligned-raw-pointer-value");
            Symbol symbol=currentProgram.getSymbolTable().getPrimarySymbol(target);if(symbol!=null)p.addProperty("targetSymbol",symbol.getName(true));
            Function fn=currentProgram.getFunctionManager().getFunctionAt(target);if(fn!=null){p.addProperty("targetFunction",fn.getName(true));p.addProperty("targetFunctionAddress",fn.getEntryPoint().toString());p.addProperty("thunk",fn.isThunk());p.addProperty("external",fn.isExternal());}
            Data data=currentProgram.getListing().getDataAt(target);if(data!=null&&data.getValue() instanceof String){String text=(String)data.getValue();p.addProperty("targetText",text.length()<=256?text:text.substring(0,256));p.addProperty("textTruncated",text.length()>256);}
            pointers.add(p);
        }
        result.add("pointers",pointers);
        JsonArray instructions=new JsonArray();InstructionIterator iterator=currentProgram.getListing().getInstructions(new AddressSet(start,end),true);n=0;
        while(iterator.hasNext()){if(n++>=256){result.addProperty("instructionsTruncated",true);break;}Instruction ins=iterator.next();JsonObject i=new JsonObject();i.addProperty("address",ins.getAddress().toString());i.addProperty("text",ins.toString());instructions.add(i);}result.add("instructions",instructions);
        result.addProperty("limitation","Loaded program memory and analyzer references only. Aligned raw pointer interpretations do not prove registration structure or semantic linkage; inspect surrounding entries. Incoming references cover the starting address only.");return result;
    }
    private JsonObject function(Function fn, boolean decompile, DecompInterface decompiler) throws Exception {
        JsonObject value=object("function");value.addProperty("name",fn.getName(true));value.addProperty("address",fn.getEntryPoint().toString());
        value.addProperty("signature",fn.getSignature().toString());value.addProperty("external",fn.isExternal());value.addProperty("thunk",fn.isThunk());
        JsonArray calls=new JsonArray(); int count=0;
        for(Function callee:fn.getCalledFunctions(monitor)) {
            if(count++>=1000){value.addProperty("calleesTruncated",true);break;}
            JsonObject call=new JsonObject();call.addProperty("name",callee.getName(true));call.addProperty("address",callee.getEntryPoint().toString());call.addProperty("external",callee.isExternal());call.addProperty("thunk",callee.isThunk());calls.add(call);
        }
        value.add("callees",calls);
        if(decompile) {
            DecompileResults result=decompiler.decompileFunction(fn,60,monitor);
            if(result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                String code=result.getDecompiledFunction().getC();
                value.addProperty("pseudocode",code.length()<=1048576?code:code.substring(0,1048576));value.addProperty("pseudocodeTruncated",code.length()>1048576);
                value.addProperty("decompilationStatus","completed");
            } else { value.addProperty("decompilationStatus","failed");value.addProperty("decompilationError",result.getErrorMessage()); }
        }
        return value;
    }
    private void linkage(String selector,String after,int limit) throws Exception {
        long skip=after.isEmpty()?0:Long.parseLong(after);if(skip<0||skip>1000000000L)throw new IllegalArgumentException("invalid linkage offset");
        long seen=0;int count=0;boolean more=false;
        if(selector.equals("imports")){
            SymbolIterator it=currentProgram.getSymbolTable().getExternalSymbols();
            while(it.hasNext()){
                monitor.checkCancelled();Symbol symbol=it.next();ExternalLocation loc=currentProgram.getExternalManager().getExternalLocation(symbol);if(loc==null)continue;
                if(seen++<skip)continue;if(count>=limit){more=true;break;}
                JsonObject item=object("native-import");item.addProperty("name",loc.getLabel()!=null?loc.getLabel():symbol.getName());item.addProperty("originalName",loc.getOriginalImportedName());item.addProperty("library",loc.getLibraryName());item.addProperty("address",symbol.getAddress().toString());item.addProperty("symbolType",symbol.getSymbolType().toString());emit(item);count++;
            }
        }else if(selector.equals("exports")){
            AddressIterator it=currentProgram.getSymbolTable().getExternalEntryPointIterator();
            while(it.hasNext()){
                monitor.checkCancelled();Address address=it.next();Symbol[] symbols=currentProgram.getSymbolTable().getSymbols(address);
                // Sort aliases for a repeatable ordinal cursor; retain every loader entry symbol.
                java.util.Arrays.sort(symbols,java.util.Comparator.comparing(Symbol::getName));
                for(Symbol symbol:symbols){
                    if(seen++<skip)continue;if(count>=limit){more=true;break;}
                    JsonObject item=object("native-export");item.addProperty("name",symbol.getName());item.addProperty("address",address.toString());item.addProperty("symbolType",symbol.getSymbolType().toString());item.addProperty("classification","ghidra-external-entry-symbol");emit(item);count++;
                }if(more)break;
            }
        }else if(selector.equals("libraries")){
            String[] names=currentProgram.getExternalManager().getExternalLibraryNames();java.util.Arrays.sort(names);
            for(String name:names){monitor.checkCancelled();if(seen++<skip)continue;if(count>=limit){more=true;break;}
                JsonObject item=object("native-library");item.addProperty("name",name);item.addProperty("library",name);item.addProperty("address","library:"+name);item.addProperty("associatedProjectPath",currentProgram.getExternalManager().getExternalLibraryPath(name));emit(item);count++;
            }
        }else throw new IllegalArgumentException("linkage selector imports, exports or libraries required");
        JsonObject end=object("end");end.addProperty("mode","linkage");end.addProperty("selectionStatus","linkage-page");end.addProperty("linkageKind",selector);end.addProperty("offset",skip);end.addProperty("records",count);end.addProperty("pageComplete",!more);if(more)end.addProperty("nextOffset",skip+count);
        end.addProperty("limitation","Ghidra loader metadata only; external-entry symbols are not a complete dynamic export resolver. Name matches do not establish ABI, loader-path resolution, runtime loading or semantic linkage.");emit(end);
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=5)throw new IllegalArgumentException("output, mode, selector, after-address, limit required");
        int limit=Integer.parseInt(args[4]);if(limit<1||limit>10000)throw new IllegalArgumentException("limit 1..10000");
        try(PrintWriter writer=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0],false),StandardCharsets.UTF_8))) {
            out=writer;
            if(analysisTimeoutOccurred())throw new IOException("Ghidra auto-analysis timed out; partial analysis is not admitted");
            JsonObject header=object("header");header.addProperty("schema","carve/native-evidence@1");header.addProperty("provider","ghidra");header.addProperty("version",Application.getApplicationVersion());
            header.addProperty("programSha256",currentProgram.getExecutableSHA256());header.addProperty("language",currentProgram.getLanguageID().toString());header.addProperty("executesTarget",false);emit(header);
            String mode=args[1];if(!java.util.Arrays.asList("function","inventory","strings","window","linkage").contains(mode))throw new IllegalArgumentException("unknown export mode");
            if(mode.equals("linkage")){linkage(args[2],args[3],limit);return;}
            boolean decompile=mode.equals("function");boolean functionPage=mode.equals("inventory")||decompile;
            String selector=args[2];String after=args[3];Address afterAddress=after.isEmpty()?null:currentProgram.getAddressFactory().getAddress(after);if(!after.isEmpty()&&afterAddress==null)throw new IllegalArgumentException("invalid cursor address");
            Address selectedAddress=decompile?currentProgram.getAddressFactory().getAddress(args[2]):null;
            int count=0;String last="";boolean hasMore=false;
            if(mode.equals("window"))emit(window(selector,limit));
            DecompInterface decompiler=new DecompInterface();
            try {
                if(decompile&&!decompiler.openProgram(currentProgram))throw new IOException("Cannot open Ghidra decompiler: "+decompiler.getLastMessage());
                FunctionIterator functions=currentProgram.getFunctionManager().getFunctions(true);
                while(functionPage&&functions.hasNext()) {
                    monitor.checkCancelled();Function fn=functions.next();String address=fn.getEntryPoint().toString();
                    if(afterAddress!=null&&fn.getEntryPoint().compareTo(afterAddress)<=0)continue;
                    if(decompile && !(fn.getName().equals(selector)||fn.getName().equals("_"+selector)||fn.getName(true).equals(selector)||(selectedAddress!=null&&fn.getEntryPoint().equals(selectedAddress))))continue;
                    if(count>=limit){hasMore=true;break;}emit(function(fn,decompile,decompiler));count++;last=address;
                }
            } finally {decompiler.dispose();}
            int strings=0;boolean stringsTruncated=false;
            if(mode.equals("strings")||(mode.equals("inventory")&&after.isEmpty())) {
                DataIterator data=currentProgram.getListing().getDefinedData(true);
                while(data.hasNext()) {
                    monitor.checkCancelled();Data item=data.next();Object raw=item.getValue();if(!(raw instanceof String))continue;
                    if(mode.equals("strings")&&((afterAddress!=null&&item.getAddress().compareTo(afterAddress)<=0)||!((String)raw).toLowerCase(Locale.ROOT).contains(selector.toLowerCase(Locale.ROOT))))continue;
                    if(strings>=(mode.equals("strings")?limit:1000)){stringsTruncated=true;break;}
                    emit(string(item));strings++;if(mode.equals("strings"))last=item.getAddress().toString();
                }
            }
            JsonObject end=object("end");end.addProperty("mode",mode);end.addProperty("functions",count);end.addProperty("strings",strings);end.addProperty("functionsComplete",functionPage&&!hasMore);end.addProperty("stringsTruncated",stringsTruncated);end.addProperty("stringsComplete",mode.equals("strings")&&!stringsTruncated);
            if(hasMore||(mode.equals("strings")&&stringsTruncated))end.addProperty("nextAddress",last);
            end.addProperty("selectionStatus",decompile?(count==1?"one-function":count==0?"not-found":"ambiguous"):mode.equals("strings")?"string-page":mode.equals("window")?"data-window":"inventory-page");
            end.addProperty("limitation","Ghidra pseudocode is reconstructed C, not original source. Dynamic calls and undeclared strings may be missing; behavior is not verified.");emit(end);
        }
    }
}
