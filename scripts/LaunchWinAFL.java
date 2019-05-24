// Launch WinAFL with current function as hook location
//@author richinseattle
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

// Usage: 
// Install DynamoRIO and WinAFL
// Add LaunchWinAFL to Ghidra scripts 
// Set one-time config in the LaunchWinAFL class below the imports
// Load target exe & dlls into Ghidra 
// Go to target func in disasm
// Run script to start fuzzing!

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectDataUtils;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.stream.Stream;

import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

import java.util.function.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public class LaunchWinAFL extends GhidraScript {	
	/*
	 * ======================================================
	 * Configuration section, modify these until I make a gui
	 * ====================================================== 
	 */
	
	// working directory for this script
	public String base_dir = System.getenv("HOMEPATH") + "\\ghidraflow";

	// base install directories for both tools
	// do not include arch subdirs, they are autodetected based on target exe
	String winafl_dir = "c:\\winafl";
	//String winafl_dir = System.getenv("WINAFL_DIR");
	String dynamorio_dir = "c:\\dynamorio";
	//String dynamorio_dir = System.getenv("DYNAMORIO_DIR");		

	// target_exe_path will be auto populated by currently opened executable
	String target_exe_path; 		
	
	// place target program arguments here, use @@ for where the fuzzed file path should go
	// by default we just pass the fuzzed file to the target exe
	String target_exe_args = "@@";		

	// auto populated by properties of current function 
	// in disassembly listing unless specified
	int target_func_argc = 0;
	long target_func_offset = 0;
	String target_func_callconv;
	
	// coverage will include all binaries in the current ghidra project unless specified here
	String[] coverage_modules;
	
	//String z = ```hm
		//	no```;
	
	// a set of inputs for your fuzz target
	// if not specified, a dialog will ask you to specify the path
	// by default it will be showing the winafl testcases directory
	public String input_dir; 

	// the top level output / working directory for WinAFL
	// subdirectories will be created for each fuzzing run 
	public String output_dir = base_dir + "\\winafl"; 

	// target arch is auto-detected unless target_exe_path was specified above
	static enum CpuArch {
		x86, 
		x64,
		Unknown
	}
	public CpuArch target_arch = CpuArch.Unknown;

	/*
	 * ======================================================
	 * Main program code follows 
	 * ======================================================
	 */
	public void run() throws Exception {				
    	/*
    	 * validate environment / config 
    	 */
		
		if(!System.getProperty("os.name").startsWith("Windows"))
		{
			popup("Sorry, this plugin only runs on Windows!");
			return;
		}

		// make working dir if not present
		File dir = new File(base_dir);
		if(!dir.exists()) 
		{
			 if(!dir.mkdir())
			 {
				popup("Error: couldn't create or access working directory\nCheck base_dir variable!");
				return;				 
			 }
		}
		
		if(target_exe_path == null)
			target_exe_path = currentProgram.getExecutablePath();

		// combine exe with args  
		var target_cmdline = String.format("%s %s", target_exe_path, target_exe_args);

		
		// currently only getting pointer size in bytes 
		if (target_arch == CpuArch.Unknown)
		{
			switch(currentProgram.getDefaultPointerSize())
			{
			case 4:
				target_arch = CpuArch.x86; 
				break;
			case 8:
				target_arch = CpuArch.x64; 
				break;
			default: 
				popup("Error: couldn't detect target arch, please specify in config!");
				return;
			}
		}
				
		if (dynamorio_dir == null) 
		{
			popup("Error: DynamoRIO not found, please set dynamorio_dir!");
			return;	
		}

		if (winafl_dir == null)
		{
			popup("Error: WinAFL not found, please set winafl_dir!");
			return;	
		}
		
		String arch_path = "";
		if(target_arch == CpuArch.x86)
		{
			arch_path = "bin32";
		} else if(target_arch == CpuArch.x64)
		{
			arch_path = "bin64";
		}
		else 
		{
			popup("Error: WinAFL doesn't support this architecture!");
			return;
		}
		
	
		/*
		 * Gather needed info
		 */		
		
		Function currentFunction = getCurrentFunction();

		if(target_exe_path == null)
			target_exe_path = currentProgram.getExecutablePath();
		
		
		if(target_func_offset == 0)
		{
			target_func_argc = currentFunction.getParameterCount();
			target_func_offset = (currentFunction.getEntryPoint().subtract(currentProgram.getImageBase()));
		}

		String target_module = new File(target_exe_path).getName();		
		String target_offset = String.format("0x%x", target_func_offset);
		int nargs = target_func_argc;
		if(target_func_callconv == null)
		{
			// FIXME: assuming this works always, unverified
			String cc = currentFunction.getCallingConventionName();
			target_func_callconv = cc.substring(2);
		}

		// add all project modules to the coverage modules list by default
		// including modules not present in process here doesn't hurt anything
		if(coverage_modules == null) 
			coverage_modules = getProgramNames();
		
		String afl_fuzz_exe_path = String.format("%s\\%s\\%s", winafl_dir, arch_path, "afl-fuzz.exe");
		String dynamorio_binpath = String.format("%s\\%s", dynamorio_dir, arch_path);
		output_dir = output_dir + "." + target_module + "." + System.currentTimeMillis();
		
		if(input_dir == null)
		{
			GhidraFileChooser gfc = new GhidraFileChooser(getState().getTool().getActiveWindow());
			gfc.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			
			gfc.setCurrentDirectory(new File(winafl_dir + "\\testcases"));

			gfc.setTitle("Input Files: Select a directory containing an input set for fuzzing");
			gfc.setStatusJustification(2); // left 
			String padding = "                       "; // to align with the input text dialogs
			gfc.setStatusText(padding + "Please select a directory containing an input set for fuzzing");
				
			File f = gfc.getSelectedFile(true);		
			if(f == null || !f.exists()) 
			{
				println("Error: Input file path not valid");
				return;
			}
			input_dir = f.getPath();
		}
		
		String afl_fuzz_opts =  
				  " -t 2000+ "
				+ " -i " + input_dir
				+ " -o " + output_dir
				+ " -D " + dynamorio_binpath;
		
		//afl_opts += " -x " + dictionary;
		
		String winafl_opts = 
				  " -target_module " + target_module  
				+ " -target_offset " + target_offset
				+ " -nargs " + nargs
				+ " -call_convention " + target_func_callconv;

		for(String mod : coverage_modules)
			winafl_opts += " -coverage_module " + mod + " ";

		winafl_opts += " -covtype edge";
		winafl_opts += " -fuzz_iterations 5000";
		//winafl_opts += " -thread_coverage";
		 
		
		// create a new timestamped output dir
		dir = new File(output_dir);
		if(!dir.exists()) 
		{
			 if(!dir.mkdir())
			 {
				popup("Error: couldn't create or access output directory!");
				return;				 
			 }
		}
		
		// we add "cmd /c start" here to get winafl running outside the ghidra process tree
		String cmdline = String.format("cmd /c start %s %s -- %s -- %s",
				afl_fuzz_exe_path,
				afl_fuzz_opts,
				winafl_opts,
				target_cmdline);

		// build child command line argv
		println("Running WinAFL cmdline: \n" + cmdline);
		String[] argv = cmdline2argv(cmdline);	
		
		// execute 
		String exec_dir = winafl_dir + "\\" + arch_path;
		exec_argv_in_dir(argv, exec_dir);

		return;
    }

	/*
	 * ======================================================
	 * Utility functions
	 * ======================================================
	 */
	public Boolean exec_argv_in_dir(String[] argv, String exec_dir)
	{
		Boolean ret = false;
		 
		ProcessBuilder builder = new ProcessBuilder();
	    builder.directory(new File(exec_dir));
	    builder.command(argv);			
	    try {
			Process process = builder.start();
			
			final InputStream is = process.getInputStream();
			byte[] msg = is.readAllBytes();
	        println(new String(msg));	        
	        ret = true;
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
		return ret;
	}
		
	public Function addr2func(Address addr)
	{
		return currentProgram.getListing().getFunctionContaining(addr);
	}
	
	public Function getCurrentFunction()
	{
		Address addr = currentAddress;
		return addr2func(addr);	
	}
	
	public String[] cmdline2argv(String cmdline)
	{
		List<String> argvList = new ArrayList<String>();
		Matcher m = Pattern.compile("([^\"]\\S*|\".+?\")\\s*").matcher(cmdline);
		while (m.find())
		{
			argvList.add(m.group(1));
		}
		return argvList.toArray(new String[0]);
	}
	
	private ArrayList<String> getFolderProgramNames ( DomainFolder domainFolder ) 
	{
		ArrayList<String> projectFiles = new ArrayList<String>();
		DomainFile[] files = domainFolder.getFiles();
		for ( DomainFile domainFile : files ) 
			projectFiles.add( domainFile.getName());
	
		DomainFolder[] folders = domainFolder.getFolders();
		for ( DomainFolder folder : folders ) 
			projectFiles.addAll(getFolderProgramNames(folder));
		  
		return projectFiles;
	}
	
	public String[] MatchStringArray(String[] array, String filter)
	{
		ArrayList<String> matches = new ArrayList<String>();
		for (String str: array) 
			if (str.contains(filter)) matches.add(str);
	
		return matches.toArray(new String[0]);
	}
	
	public String[] getProgramNames() 
	{
		PluginTool tool = state.getTool();
		Project project = tool.getProject();
		ProjectData projectData = project.getProjectData();
		DomainFolder rootFolder = projectData.getRootFolder();
		return getFolderProgramNames(rootFolder).toArray(new String[0]);
	}
	
	public String[] getExeNames() 
	{
		return MatchStringArray(getProgramNames(), ".exe");
	}
	
	public String[] getDllNames() 
	{
		return MatchStringArray(getProgramNames(), ".dll");
	}
	
	public String[] getEnvp() 
	{
		Map<String,String> envs = System.getenv();
		String[] envp = new String[envs.size()];
		
		int i = 0;
		for (Map.Entry<String,String> e : envs.entrySet()) 
			envp[i++] = e.getKey()+'+'+e.getValue();
		
		return envp;
	}
}