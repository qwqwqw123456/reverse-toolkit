// Ghidra headless post-script v4.2: 智能降噪 + 加权排序 + callees 递归导出
// 升级点：
//   1. 黑名单过滤：external、thunk、空函数体、_ 开头库函数、LIB_FUNCTIONS
//   2. 危险 API 三级分级：CRITICAL(权重10) / HIGH(权重5) / MEDIUM(权重2)
//   3. 加权得分排序：得分 = 极高危*10 + 高危*5 + 中危*2 + XREF*1
//   4. Top N 核心函数 + 直接 callees（1 层深度，Set 去重）
//   5. [TOP] / [CALLEE] / [DANGEROUS] 标记，帮 AI 理清调用层级
// 用法: analyzeHeadless <proj_dir> <proj> -import <bin> -scriptPath <dir> -postScript ExportDecompiled.java <outdir> [topN]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.listing.Program;
import java.io.File;
import java.io.PrintWriter;
import java.util.*;

public class ExportDecompiled extends GhidraScript {

	// 危险 API 分级：极高危 / 高危 / 中危 / 基础库（不计分）
	private static final Set<String> CRITICAL_APIS = new HashSet<>(Arrays.asList(
		"system", "popen", "execve", "execl", "execv",
		"WinExec", "ShellExecute", "CreateProcessA", "CreateProcessW",
		"socket", "connect", "InternetOpenA", "InternetOpenW", "URLDownloadToFileA", "URLDownloadToFileW",
		"CreateRemoteThread", "WriteProcessMemory", "OpenProcess", "VirtualAllocEx"
	));

	private static final Set<String> HIGH_APIS = new HashSet<>(Arrays.asList(
		"CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
		"RegOpenKeyA", "RegOpenKeyW", "RegSetValueA", "RegSetValueW",
		"VirtualAlloc", "mmap", "CreateServiceA", "CreateServiceW",
		"StartServiceA", "StartServiceW", "CryptEncrypt", "CryptDecrypt"
	));

	private static final Set<String> MEDIUM_APIS = new HashSet<>(Arrays.asList(
		"strcpy", "strcat", "sprintf", "vsprintf", "gets",
		"memcpy", "memmove"
	));

	// 库函数黑名单：这些函数不参与 Top 排序，只在 callees 里出现
	private static final Set<String> LIB_FUNCTIONS = new HashSet<>(Arrays.asList(
		"malloc", "free", "realloc", "strlen", "memset", "memcmp",
		"printf", "fprintf", "sprintf", "snprintf", "scanf",
		"puts", "fputs", "fgets", "fopen", "fread", "fwrite", "fclose",
		"close", "read", "write", "open", "lseek",
		"strcmp", "strncmp", "strchr", "strrchr", "strstr", "strdup",
		"strcpy", "strncpy", "strcat", "strncat",
		"__stack_chk_fail", "__errno_location", "__ctype_b_loc", "__ctype_get_mb_cur_max",
		"dcgettext", "dcigettext", "gettext", "bindtextdomain",
		"sigemptyset", "sigprocmask", "signal",
		"__libc_start_main", "__cxa_finalize", "_init", "_fini", "_start"
	));

	@Override
	protected void run() throws Exception {
		String outDirPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/rea_out";
		int topN = getScriptArgs().length > 1 ? Integer.parseInt(getScriptArgs()[1]) : 20;
		File outDir = new File(outDirPath);
		outDir.mkdirs();

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);

		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();

		// ===== 函数补充识别（stripped 场景修复）=====
		MemoryBlock textBlock = currentProgram.getMemory().getBlock(".text");
		if (textBlock != null) {
			Address ta = textBlock.getStart();
			long maxScan = textBlock.getSize();
			long scanned = 0;
			while (ta != null && ta.compareTo(textBlock.getEnd()) <= 0 && scanned < maxScan) {
				scanned++;
				if (fm.getFunctionContaining(ta) != null) {
					Function cf = fm.getFunctionContaining(ta);
					ta = cf.getBody().getMaxAddress().add(1);
					continue;
				}
				Instruction ins = listing.getInstructionAt(ta);
				if (ins == null) {
					try {
						boolean d = disassemble(ta);
						ins = d ? listing.getInstructionAt(ta) : null;
					} catch (Exception e) {
						ins = null;
					}
				}
				if (ins != null) {
					String m = ins.getMnemonicString().toUpperCase();
					boolean prologue = m.equals("PUSH") || m.equals("ENTER") || m.equals("STMFD")
						|| (m.equals("SUB") && ins.getDefaultOperandRepresentation(1).startsWith("0x"));
					if (!prologue && m.equals("ENDBR64")) {
						Instruction next = ins.getNext();
						if (next != null) {
							String nm = next.getMnemonicString().toUpperCase();
							prologue = nm.equals("PUSH") || nm.equals("ENTER")
								|| (nm.equals("SUB") && next.getDefaultOperandRepresentation(1).startsWith("0x"));
						}
					}
					if (prologue) {
						try {
							ghidra.program.model.address.AddressSet body = new ghidra.program.model.address.AddressSet();
							Address cur = ta;
							while (cur != null && cur.compareTo(textBlock.getEnd()) <= 0) {
								Instruction i = listing.getInstructionAt(cur);
								if (i == null) break;
								body.addRange(cur, i.getMaxAddress());
								String mm = i.getMnemonicString().toUpperCase();
								if (mm.equals("RET") || mm.equals("RETN") || mm.equals("JMP") || mm.startsWith("JMP")) {
									break;
								}
								cur = i.getMaxAddress().add(1);
							}
							Function nf = fm.createFunction(null, ta, body, ghidra.program.model.symbol.SourceType.ANALYSIS);
							if (nf != null) {
								ta = nf.getBody().getMaxAddress().add(1);
								continue;
							}
						} catch (Exception e) {
							println("REC_ERR " + ta + " " + e.getClass().getSimpleName() + ": " + e.getMessage());
						}
					}
				}
				ta = ta.add(1);
			}
			println("FUNCTION_RECOVERY: scanned " + scanned + " bytes in .text");
		}

		// ===== 第一遍：收集所有函数，计算 XREF 数量和危险等级得分 =====
		Map<Function, Integer> funcXrefCount = new HashMap<>();
		Map<Function, Boolean> funcDangerous = new HashMap<>();
		Map<Function, Integer> funcScore = new HashMap<>(); // 加权得分
		List<Function> allFuncs = new ArrayList<>();
		List<Function> libFuncs = new ArrayList<>(); // 库函数，不参与 Top 排序

		FunctionIterator funcs = fm.getFunctions(true);
		while (funcs.hasNext()) {
			Function f = funcs.next();
			// 过滤：外部函数、Thunk、空函数体
			if (f.isExternal()) continue;
			if (f.isThunk()) continue;
			if (f.getBody().isEmpty()) continue;
			
			String fname = f.getName();
			// 过滤：以 _ 开头的库函数（C 标准库命名习惯）
			boolean isLib = fname.startsWith("_") || fname.startsWith("std::") || LIB_FUNCTIONS.contains(fname);
			
			// 计算 XREF 数量（被多少地方引用）
			int xrefCount = 0;
			ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
			while (refs.hasNext()) {
				refs.next();
				xrefCount++;
			}
			funcXrefCount.put(f, xrefCount);

			// 检查调用的危险 API，计算加权得分
			int criticalCount = 0;
			int highCount = 0;
			int mediumCount = 0;
			java.util.Set<Function> called = f.getCalledFunctions(monitor);
			for (Function callee : called) {
				if (callee == null) continue;
				String cname = callee.getName();
				if (CRITICAL_APIS.contains(cname)) criticalCount++;
				else if (HIGH_APIS.contains(cname)) highCount++;
				else if (MEDIUM_APIS.contains(cname)) mediumCount++;
			}
			boolean dangerous = (criticalCount + highCount + mediumCount) > 0;
			funcDangerous.put(f, dangerous);
			
			// 加权得分 = 极高危*10 + 高危*5 + 中危*2 + XREF*1
			int score = criticalCount * 10 + highCount * 5 + mediumCount * 2 + xrefCount;
			funcScore.put(f, score);
			
			if (isLib) {
				libFuncs.add(f);
			} else {
				allFuncs.add(f);
			}
		}

		// 按加权得分排序（用户自定义函数）
		allFuncs.sort((a, b) -> funcScore.get(b) - funcScore.get(a));
		// 库函数按 XREF 排序（放后面）
		libFuncs.sort((a, b) -> funcXrefCount.get(b) - funcXrefCount.get(a));
		
		// 合并：用户自定义函数在前，库函数在后
		allFuncs.addAll(libFuncs);

		println("COLLECTED " + allFuncs.size() + " functions, sorted by weighted score");

		// ===== 第二遍：导出 =====
		PrintWriter index = new PrintWriter(new File(outDir, "_index.txt"), "UTF-8");
		PrintWriter skipped = new PrintWriter(new File(outDir, "_skipped.txt"), "UTF-8");
		PrintWriter callgraph = new PrintWriter(new File(outDir, "_callgraph.txt"), "UTF-8");
		PrintWriter dangerousList = new PrintWriter(new File(outDir, "_dangerous.txt"), "UTF-8");

		int exportedCount = 0;
		int skippedCount = 0;

		// 记录已导出的函数（防止重复导出）
		java.util.Set<Function> exportedFuncs = new java.util.HashSet<>();

		// 第一步：收集 Top N 函数 + 它们的直接 callees（1 层深度）
		java.util.List<Function> toExport = new java.util.ArrayList<>();
		java.util.Map<Function, String> funcLayer = new java.util.HashMap<>();

		for (int i = 0; i < Math.min(topN, allFuncs.size()); i++) {
			Function f = allFuncs.get(i);
			if (!exportedFuncs.contains(f)) {
				exportedFuncs.add(f);
				toExport.add(f);
				funcLayer.put(f, "[TOP]");
			}
			// 收集直接 callees（1 层深度）
			java.util.Set<Function> callees = f.getCalledFunctions(monitor);
			for (Function callee : callees) {
				if (callee != null && !callee.isExternal() && !exportedFuncs.contains(callee)) {
					exportedFuncs.add(callee);
					toExport.add(callee);
					funcLayer.put(callee, "[CALLEE]");
				}
			}
		}

		// 第二步：导出所有收集到的函数
		for (int i = 0; i < allFuncs.size(); i++) {
			Function f = allFuncs.get(i);
			int xref = funcXrefCount.get(f);
			boolean isDangerous = funcDangerous.get(f);

			// 调用图
			java.util.Set<Function> called = f.getCalledFunctions(monitor);
			for (Function callee : called) {
				String cn = callee != null ? callee.getName() : "?";
				callgraph.println(f.getName() + " -> " + cn);
			}

			// 标记危险函数
			if (isDangerous) {
				dangerousList.println(f.getEntryPoint() + "\t" + f.getName() + "\txref=" + xref);
			}

			// 只导出收集到的函数（Top N + callees）
			if (!exportedFuncs.contains(f)) {
				// 不在导出列表里，只列清单
				index.println(f.getEntryPoint() + "\t" + f.getName() + "\t" + f.getSignature() 
					+ "\t" + f.getBody().getNumAddresses() + " bytes\txref=" + xref + (isDangerous ? "\t[DANGEROUS]" : ""));
				continue;
			}

			// 反编译
			DecompileResults res = null;
			try {
				res = decomp.decompileFunction(f, 90, monitor);
			} catch (Exception e) {
				skipped.println(f.getEntryPoint() + "\t" + f.getName() + "\tEXC " + e.getClass().getSimpleName());
				skippedCount++;
				continue;
			}
			if (res == null || res.getDecompiledFunction() == null) {
				skipped.println(f.getEntryPoint() + "\t" + f.getName() + "\tNO_DECOMP (timeout?)");
				skippedCount++;
				continue;
			}

			String addr = f.getEntryPoint().toString();
			String safeName = f.getName().replaceAll("[^A-Za-z0-9_.-]", "_");
			String layer = funcLayer.get(f);
			index.println(addr + "\t" + f.getName() + "\t" + f.getSignature() 
				+ "\t" + f.getBody().getNumAddresses() + " bytes\txref=" + xref + (isDangerous ? "\t[DANGEROUS]" : layer));

			File cFile = new File(outDir, addr + "_" + safeName + ".c");
			PrintWriter pw = new PrintWriter(cFile, "UTF-8");
			pw.println("// Function: " + f.getName() + " @ " + addr);
			pw.println("// Signature: " + f.getSignature());
			pw.println("// Body size: " + f.getBody().getNumAddresses() + " bytes");
			pw.println("// XREF count: " + xref);
			pw.println("// Dangerous: " + (isDangerous ? "YES" : "NO"));
			pw.println("// Layer: " + layer);
			pw.println("/*");
			pw.print(res.getDecompiledFunction().getC());
			pw.println("*/");
			pw.close();
			exportedCount++;
		}

		index.close();
		skipped.close();
		callgraph.close();
		dangerousList.close();

		// ===== 字符串 XRef =====
		PrintWriter xref = new PrintWriter(new File(outDir, "_xref_strings.txt"), "UTF-8");
		int strCount = 0;
		for (Data d : listing.getDefinedData(true)) {
			if (d.hasStringValue()) {
				String val = d.getDefaultValueRepresentation();
				if (val.length() > 400) val = val.substring(0, 400) + "...";
				Address refAddr = d.getAddress();
				StringBuilder callers = new StringBuilder();
				ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(refAddr);
				int rc = 0;
				while (refs.hasNext() && rc < 20) {
					Reference r = refs.next();
					Function cf = fm.getFunctionContaining(r.getFromAddress());
					if (callers.length() > 0) callers.append(", ");
					callers.append(cf != null ? cf.getName() + " @" + r.getFromAddress() : "data @" + r.getFromAddress());
					rc++;
				}
				xref.println(val + "\t<- referenced by: " + (callers.length() == 0 ? "(none)" : callers.toString()));
				strCount++;
			}
		}
		xref.close();

		// ===== 汇总元数据 =====
		PrintWriter meta = new PrintWriter(new File(outDir, "_meta.txt"), "UTF-8");
		meta.println("program=" + currentProgram.getName());
		meta.println("total_functions=" + allFuncs.size());
		meta.println("functions_exported_full=" + exportedCount);
		meta.println("functions_listed_only=" + (allFuncs.size() - exportedCount - skippedCount));
		meta.println("functions_skipped=" + skippedCount);
		meta.println("dangerous_functions=" + countDangerous(funcDangerous));
		meta.println("defined_strings=" + strCount);
		meta.println("top_n=" + topN);
		meta.close();

		println("EXPORTED " + exportedCount + " full functions (top " + topN + " by weighted score), " 
			+ countDangerous(funcDangerous) + " dangerous, " + strCount + " strings");
	}

	private int countDangerous(Map<Function, Boolean> map) {
		int c = 0;
		for (boolean b : map.values()) if (b) c++;
		return c;
	}
}
