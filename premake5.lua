solution "libhooker"
	configurations { "x86_64", "i386", "arm" }
	
	flags { "Symbols" }

	platforms { "linux" }
	
	language "C"
	includedirs { "include" }
	
	files { "src/common/*.c" }
	
	targetdir "bin"
	targetprefix("")
	
	premake.tools.cross_gcc         = {}
	cross_prefix = os.getenv("CROSS_COMPILE")
	
	if cross_prefix then
		local cross_gcc                 = premake.tools.cross_gcc
		local gcc                     = premake.tools.gcc

		cross_gcc.getcflags             = gcc.getcflags
		cross_gcc.getcxxflags           = gcc.getcxxflags
		cross_gcc.getforceincludes      = gcc.getforceincludes
		cross_gcc.getldflags            = gcc.getldflags
		cross_gcc.getcppflags           = gcc.getcppflags
		cross_gcc.getdefines            = gcc.getdefines
		cross_gcc.getundefines          = gcc.getundefines
		cross_gcc.getincludedirs        = gcc.getincludedirs
		cross_gcc.getLibraryDirectories = gcc.getLibraryDirectories
		cross_gcc.getlinks              = gcc.getlinks
		cross_gcc.getmakesettings       = gcc.getmakesettings

		function cross_gcc.gettoolname (cfg, tool)  
			local prefix = cross_prefix
			if tool == "cc" then
				name = prefix .. "gcc"  
			elseif tool == "cxx" then
				name = prefix .. "g++"
			elseif tool == "ar" then
				name = prefix .. "ar"
			else
				name = nil
			end
			return name
		end
		
		filter "configurations:arm"
			toolset "cross_gcc"
	end

	filter "configurations:i386"
		architecture "x86"
		links { "capstone" }
	
	filter "configurations:x86_64"
		architecture "x86_64"
		links { "capstone" }
	
	filter "platforms:linux"
		system "linux"
		defines { "_GNU_SOURCE" }
		buildoptions {
			"-fPIC", "-Wall"
		}

	project "needle"
		kind "ConsoleApp"
		files {
			"src/needle/*.c"
		}

		filter "configurations:i386"
			files {
				"src/interface/cpu/intel/common_intel.c",
				"src/interface/cpu/intel/cpu_i386.c",
			}
		
		filter "configurations:x86_64"
			files {
				"src/interface/cpu/intel/common_intel.c",
				"src/interface/cpu/intel/cpu_x86_64.c",
			}
		
		filter "configurations:arm"
			files { "src/interface/cpu/arm/cpu_arm.c" }

		filter "platforms:linux"
			files {
				"src/interface/inject/linux/*.c",
				"src/interface/exe/elf/*.c"
			}
		
	project "testapp"
		kind "ConsoleApp"
		files {
			"src/testapp/*.c"
		}

	group "Modules"
		project "lh_basemod"
			kind "StaticLib"
			links { "lh_common" }
			files { "src/basemod/*.c" }

		project "lhm_sample"
			kind "SharedLib"
			files { "modules/sample/*.c" }
			links { "lh_basemod" }
