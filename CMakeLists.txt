#======================= Project ======================
cmake_minimum_required(VERSION 3.25)
project(Packet-Sniffer)

# ====================== Setup: compiler options ==================
# using CPP+20 standerad
set(CMAKE_CXX_STANDARD 20)
# compile commands for lsp
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# default to debug builds
set(CMAKE_BUILD_TYPE Debug)

# additional compiler flags
# for gcc and clang
set(GCC_COVERAGE_COMPILE_FLAGS "")
# for MSVC(microsoft's compiler)
set(MSVC_COVERAGE_COMPILE_FLAGS "/MP")

# apply the flags
if(NOT MSVC)
	set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")
else()
	set(CMAKE_CXX_FLAGS	"${CMAKE_CXX_FLAGS} ${MSVC_COVERAGE_COMPILE_FLAGS}")
endif()

# Link compile commands in root if it's not visual studio
# for lsp in vscode and neovim
if (NOT CMAKE_GENERATOR MATCHES "Visual Studio")
  execute_process(
  	COMMAND ${CMAKE_COMMAND} -E create_symlink
  		${CMAKE_BINARY_DIR}/compile_commands.json
  		${CMAKE_SOURCE_DIR}/compile_commands.json
  )
endif()

# ================== Application related =============================
file(
	GLOB_RECURSE # recursive
	SRC # variable to store the source files and headers
	CONFIGURE_DEPENDS # make a dependency
	"src/*.hpp"
	"src/*.cpp"
)

# takes all the source files found and add them to make a executable (our app)
add_executable(packet-sniffer ${SRC})


