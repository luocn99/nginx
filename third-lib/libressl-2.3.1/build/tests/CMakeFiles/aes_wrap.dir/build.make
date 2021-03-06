# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.0

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lancelot/git/nginx/third-lib/libressl-2.3.1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/aes_wrap.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/aes_wrap.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/aes_wrap.dir/flags.make

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o: tests/CMakeFiles/aes_wrap.dir/flags.make
tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o: ../tests/aes_wrap.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/aes_wrap.dir/aes_wrap.c.o   -c /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/aes_wrap.c

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/aes_wrap.dir/aes_wrap.c.i"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/aes_wrap.c > CMakeFiles/aes_wrap.dir/aes_wrap.c.i

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/aes_wrap.dir/aes_wrap.c.s"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/aes_wrap.c -o CMakeFiles/aes_wrap.dir/aes_wrap.c.s

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.requires:
.PHONY : tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.requires

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.provides: tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.requires
	$(MAKE) -f tests/CMakeFiles/aes_wrap.dir/build.make tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.provides.build
.PHONY : tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.provides

tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.provides.build: tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o

# Object files for target aes_wrap
aes_wrap_OBJECTS = \
"CMakeFiles/aes_wrap.dir/aes_wrap.c.o"

# External object files for target aes_wrap
aes_wrap_EXTERNAL_OBJECTS =

tests/aes_wrap: tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o
tests/aes_wrap: tests/CMakeFiles/aes_wrap.dir/build.make
tests/aes_wrap: ssl/libssl.a
tests/aes_wrap: crypto/libcrypto.a
tests/aes_wrap: tests/CMakeFiles/aes_wrap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable aes_wrap"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/aes_wrap.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/aes_wrap.dir/build: tests/aes_wrap
.PHONY : tests/CMakeFiles/aes_wrap.dir/build

tests/CMakeFiles/aes_wrap.dir/requires: tests/CMakeFiles/aes_wrap.dir/aes_wrap.c.o.requires
.PHONY : tests/CMakeFiles/aes_wrap.dir/requires

tests/CMakeFiles/aes_wrap.dir/clean:
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/aes_wrap.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/aes_wrap.dir/clean

tests/CMakeFiles/aes_wrap.dir/depend:
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lancelot/git/nginx/third-lib/libressl-2.3.1 /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests/CMakeFiles/aes_wrap.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/aes_wrap.dir/depend

