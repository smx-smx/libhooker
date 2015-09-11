premake.tools.cross_gcc = {}
cross_prefix = os.getenv("CROSS_COMPILE")
if cross_prefix then
	local cross_gcc                 = premake.tools.cross_gcc
	local gcc                       = premake.tools.gcc

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
		elseif tool == "ld" then
			name = prefix .. "ld"
		else
			name = nil
		end
		return name
	end
end