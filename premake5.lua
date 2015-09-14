solution "libhooker"
	configurations {
		"x86_64", "i386",
		"armv5", "armv7", "armthumb2", "arm64",
		"ppc32", "ppc64",
		"tilegx",
		"mips32", "mips64",
		"sparc32",
		"auto"
	}
	
	flags { "Symbols" }

	platforms { "linux" }
	
	language "C"
	includedirs { "include" }
	
	files { "src/common/*.c" }
	
	targetdir "bin"
	targetprefix("")
	
	include("cross.lua")
	toolset "cross_gcc"

	filter "configurations:auto"
		defines { "SLJIT_CONFIG_AUTO" }
		links { "capstone" }

	filter "configurations:i386"
		defines { "SLJIT_CONFIG_X86_32" }
		architecture "x86"
		links { "capstone" }
	
	filter "configurations:x86_64"
		defines { "SLJIT_CONFIG_X86_64" }
		architecture "x86_64"
		links { "capstone" }

	filter "configurations:armv5"
		defines { "SLJIT_CONFIG_ARM_V5" }

	filter "configurations:armv7"
		defines { "SLJIT_CONFIG_ARM_V7" }

	filter "configurations:armthumb2"
		defines { "SLJIT_CONFIG_ARM_THUMB2" }

	filter "configurations:arm64"
		defines { "SLJIT_CONFIG_ARM_64" }

	filter "configurations:ppc32"
		defines { "SLJIT_CONFIG_PPC_32" }

	filter "configurations:ppc64"
		defines { "SLJIT_CONFIG_PPC_64" }

	filter "configurations:mips32"
		defines { "SLJIT_CONFIG_MIPS_32" }

	filter "configurations:mips64"
		defines { "SLJIT_CONFIG_MIPS_64" }

	filter "configurations:sparc32"
		defines { "SLJIT_CONFIG_SPARC_32" }

	filter "configurations:tilegx"
		defines { "SLJIT_CONFIG_TILEGX" }
	
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

		includedirs { "include/sljit" }
		
		files {
			"src/interface/cpu/sljit/sljitLir.c",
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
		
		filter "configurations:arm32"
			files {
				"src/interface/cpu/arm/cpu_arm.c"
			}

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
			links { "lh_common", "lh_basemod" }

		if os.isfile("modules.lua") then
			include("modules.lua");
		end
