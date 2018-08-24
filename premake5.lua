function lh_basemod()
	links { "lh_common", "lh_basemod" }
end

function lh_injmod()
	links { "lh_common", "lh_basemod", "lh_injmod", "lh_ifcpu", } --"capstone" }
end

function lh_lgmod()
	links { "lh_common", "lh_basemod", "lh_lgmod" }
end

function lh_sljitmod()
	links { "lh_common", "lh_basemod", "lh_sljit" }
end

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
	includeexternal("sljit.lua");

	targetdir "bin"
	targetprefix("")


	filter "platforms:linux"
		system "linux"
		defines {
			"_GNU_SOURCE",
			"LH_JUMP_ABS",
			"PLATFORM_LINUX"
		}
		pic "on"
		buildoptions {
			"-std=c99"
			--"-Wall"
		}


	include("cross.lua")
	toolset "cross_gcc"

	filter "configurations:i386"
		architecture "x86"
		libdirs { "/usr/lib32/**" }

	filter "configurations:x86_64"
		architecture "x86_64"

	project "lh_common"
		kind "StaticLib"
		files {
			"src/common/lh_common.c"
		}

	project "lh_ifcpu"
		kind "StaticLib"
		files {
			"src/interface/cpu/cpu_common.c"
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

		filter "configurations:armv5"
			files { "src/interface/cpu/arm/cpu_arm.c" }

		filter "configurations:armv7"
			files { "src/interface/cpu/arm/cpu_arm.c" }

	group "Helpers"
		project "lh_basemod"
			kind "StaticLib"
			links { "lh_common" }
			files { "src/helpers/base/*.c" }

		project "lh_injmod"
			kind "StaticLib"
			links { "lh_common" }
			files {
				"src/helpers/ext/*.c"
			}

		project "lh_sljit"
			kind "StaticLib"
			links { "lh_common" }
			files {
				"src/interface/cpu/sljit/sljitLir.c"
			}

		project "lh_lgmod"
			kind "StaticLib"
			links { "lh_common" }
			files {
				"src/helpers/lg/*.c"
			}



	project "needle"
		kind "ConsoleApp"
		links { "lh_common", "lh_ifcpu", "lh_sljit" }

		files {
			"src/needle/needle.c"
		}

		filter "configurations:i386"
			links { "capstone" }

		filter "configurations:x86_64"
			links { "capstone" }

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
		-- libdl somehow required when using ASM hooks
		links { "lh_common", "dl" }

	project "lh_preload"
		kind "SharedLib"
		defines {
			"LH_PRELOAD"
		}
		files {
			"src/needle/needle.c",
			"src/interface/inject/linux/inject_preload.c",
			"src/interface/inject/linux/inject_linux.c",
			"src/interface/exe/elf/*.c"
		}

		filter "configurations:i386"
			links { "capstone" }

		filter "configurations:x86_64"
			links { "capstone" }		

		links { "dl", "lh_common" }
		lh_injmod()

	group "Modules"
		project "lhm_sample"
			kind "SharedLib"
			files { "modules/sample/*.c" }
			lh_basemod()

		project "lhm_sample_sljit"
			kind "SharedLib"
			files { "modules/sample_sljit/*.c" }
			lh_basemod()
			lh_injmod()
			lh_sljitmod()

		dofileopt("modules.lua");
