includedirs { "include/sljit" }
defines { "SLJIT_DEBUG=0" }

filter "configurations:auto"
	defines { "SLJIT_CONFIG_AUTO" }

filter "configurations:i386"
	defines { "SLJIT_CONFIG_X86_32" }

filter "configurations:x86_64"
	defines { "SLJIT_CONFIG_X86_64" }

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