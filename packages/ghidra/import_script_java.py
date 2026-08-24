"""Java import script for applying RAPTOR enrichments to Ghidra.

Written to a tempfile at runtime and passed to ``analyzeHeadless
-postScript``. Java (not Python): headless Ghidra 11+ ships no Jython
interpreter, and PyGhidra scripts need a configured CPython venv the
sandbox does not provide — a compiled-on-the-fly GhidraScript is the
only interpreter-free channel. Mirrors the pyghidra apply logic in
``bridge._apply_enrichments_pyghidra``.
"""

IMPORT_SCRIPT_JAVA = r"""
// RAPTOR enrichments import — applies comments, bookmarks, and new
// functions from an enrichments JSON to the processed program.
// Invoked via: analyzeHeadless ... -postScript ImportRaptor.java <enrichments.json>
//@category RAPTOR

import java.io.FileReader;

import com.google.gson.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.database.function.OverlappingFunctionException;

public class ImportRaptor extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("ImportRaptor.java requires an enrichments JSON path");
            return;
        }

        JsonObject enrichments;
        try (FileReader reader = new FileReader(args[0])) {
            enrichments = JsonParser.parseReader(reader).getAsJsonObject();
        }

        Program program = currentProgram;
        int nComments = applyComments(program, enrichments);
        int nBookmarks = applyBookmarks(program, enrichments);
        int nFunctions = applyFunctions(program, enrichments);

        println(String.format(
            "RAPTOR import: %d comments, %d bookmarks, %d functions",
            nComments, nBookmarks, nFunctions));
    }

    private CommentType commentType(String kind) {
        switch (kind) {
            case "plate": return CommentType.PLATE;
            case "pre":   return CommentType.PRE;
            case "post":  return CommentType.POST;
            default:      return CommentType.EOL;
        }
    }

    private Address toAddress(Program program, JsonObject entry) {
        if (entry.has("address") && !entry.get("address").isJsonNull()) {
            long raw = entry.get("address").getAsLong();
            if (raw >= 0) {
                AddressSpace space =
                    program.getAddressFactory().getDefaultAddressSpace();
                Address resolved = space.getAddress(raw);
                // A stale or wrong-base address that hits no code
                // unit falls through to name resolution below.
                if (program.getListing().getCodeUnitAt(resolved) != null) {
                    return resolved;
                }
            }
        }
        // Name-keyed entry: resolve via the program's own function
        // index. Doing this here saves the caller a whole
        // analyzeHeadless invocation that existed only to build a
        // name-to-address map.
        if (entry.has("function") && !entry.get("function").isJsonNull()) {
            String name = entry.get("function").getAsString();
            if (!name.isEmpty()) {
                java.util.List<Function> matches =
                    currentProgram.getListing()
                        .getGlobalFunctions(name);
                if (matches.size() > 1) {
                    println(String.format(
                        "RAPTOR import: name '%s' matches %d "
                        + "definitions - using the first",
                        name, matches.size()));
                }
                if (!matches.isEmpty()) {
                    return matches.get(0).getEntryPoint();
                }
            }
        }
        return null;
    }

    private int applyComments(Program program, JsonObject enrichments) {
        if (!enrichments.has("comments")) {
            return 0;
        }
        Listing listing = program.getListing();
        int count = 0;
        for (JsonElement el : enrichments.getAsJsonArray("comments")) {
            JsonObject entry = el.getAsJsonObject();
            Address addr = toAddress(program, entry);
            if (addr == null) {
                continue;
            }
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu == null) {
                continue;
            }
            CommentType ct = commentType(
                entry.has("kind") ? entry.get("kind").getAsString() : "eol");
            String text = entry.get("text").getAsString();
            String existing = cu.getComment(ct);
            if (existing != null) {
                if (existing.contains(text)) {
                    continue;
                }
                text = existing + "\n" + text;
            }
            cu.setComment(ct, text);
            count++;
        }
        return count;
    }

    private int applyBookmarks(Program program, JsonObject enrichments) {
        if (!enrichments.has("bookmarks")) {
            return 0;
        }
        int count = 0;
        for (JsonElement el : enrichments.getAsJsonArray("bookmarks")) {
            JsonObject entry = el.getAsJsonObject();
            Address addr = toAddress(program, entry);
            if (addr == null) {
                continue;
            }
            String btype = entry.has("type")
                ? entry.get("type").getAsString() : "RAPTOR";
            String category = entry.has("category")
                ? entry.get("category").getAsString() : "Finding";
            String comment = entry.has("comment")
                ? entry.get("comment").getAsString() : "";
            program.getBookmarkManager()
                .setBookmark(addr, btype, category, comment);
            count++;
        }
        return count;
    }

    private int applyFunctions(Program program, JsonObject enrichments) {
        if (!enrichments.has("new_functions")) {
            return 0;
        }
        FunctionManager fm = program.getFunctionManager();
        int count = 0;
        for (JsonElement el : enrichments.getAsJsonArray("new_functions")) {
            JsonObject entry = el.getAsJsonObject();
            Address addr = toAddress(program, entry);
            if (addr == null) {
                continue;
            }
            if (fm.getFunctionAt(addr) != null) {
                continue;
            }
            String name = entry.has("name")
                ? entry.get("name").getAsString()
                : String.format("raptor_%x", addr.getOffset());
            try {
                Function func = fm.createFunction(
                    name, addr, null, SourceType.USER_DEFINED);
                if (func != null) {
                    count++;
                }
            } catch (InvalidInputException | OverlappingFunctionException e) {
                // A function the disassembly disagrees with is a skip,
                // not a failed import.
            }
        }
        return count;
    }
}
"""
