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
include tests/CMakeFiles/pkcs7test.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/pkcs7test.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/pkcs7test.dir/flags.make

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o: tests/CMakeFiles/pkcs7test.dir/flags.make
tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o: ../tests/pkcs7test.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/pkcs7test.dir/pkcs7test.c.o   -c /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/pkcs7test.c

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/pkcs7test.dir/pkcs7test.c.i"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/pkcs7test.c > CMakeFiles/pkcs7test.dir/pkcs7test.c.i

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/pkcs7test.dir/pkcs7test.c.s"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests/pkcs7test.c -o CMakeFiles/pkcs7test.dir/pkcs7test.c.s

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.requires:
.PHONY : tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.requires

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.provides: tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.requires
	$(MAKE) -f tests/CMakeFiles/pkcs7test.dir/build.make tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.provides.build
.PHONY : tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.provides

tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.provides.build: tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o

# Object files for target pkcs7test
pkcs7test_OBJECTS = \
"CMakeFiles/pkcs7test.dir/pkcs7test.c.o"

# External object files for target pkcs7test
pkcs7test_EXTERNAL_OBJECTS =

tests/pkcs7test: tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o
tests/pkcs7test: tests/CMakeFiles/pkcs7test.dir/build.make
tests/pkcs7test: ssl/libssl.a
tests/pkcs7test: crypto/libcrypto.a
tests/pkcs7test: tests/CMakeFiles/pkcs7test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable pkcs7test"
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/pkcs7test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/pkcs7test.dir/build: tests/pkcs7test
.PHONY : tests/CMakeFiles/pkcs7test.dir/build

tests/CMakeFiles/pkcs7test.dir/requires: tests/CMakeFiles/pkcs7test.dir/pkcs7test.c.o.requires
.PHONY : tests/CMakeFiles/pkcs7test.dir/requires

tests/CMakeFiles/pkcs7test.dir/clean:
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/pkcs7test.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/pkcs7test.dir/clean

tests/CMakeFiles/pkcs7test.dir/depend:
	cd /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lancelot/git/nginx/third-lib/libressl-2.3.1 /home/lancelot/git/nginx/third-lib/libressl-2.3.1/tests /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests /home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests/CMakeFiles/pkcs7test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/pkcs7test.dir/depend
