solution "libhooker"
	configurations { "x86_64", "i386","arm" }
	
	flags { "Symbols" }

	platforms { "linux" }
	
	language "C"
	includedirs { "include" }
	
	targetdir "bin"
	targetprefix("")

	filter "configurations:i386"
		architecture "x86"
		links { "capstone" }
	
	filter "configurations:x86_64"
		architecture "x86_64"
		links { "capstone" }
	
	filter "configurations:arm"
		makesettings [[
			ifeq ($(strip $(CROSS_COMPILE)),)
				$(error "CROSS_COMPILE environment variable is not set")'
			endif
		]]
	
	filter "platforms:linux"
		system "linux"
		defines { "_GNU_SOURCE" }
		buildoptions {
			"-fPIC", "-Wall"
		}

	files { "src/common/*.c" }

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
			files { "src/interface/cpu/cpu_arm.c" }

		filter "platforms:linux"
			files {
				"src/interface/os/linux/*.c",
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
