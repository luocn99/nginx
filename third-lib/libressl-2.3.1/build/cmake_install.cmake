# Install script for directory: /home/lancelot/git/nginx/third-lib/libressl-2.3.1

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/crypto/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/ssl/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/apps/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tls/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/include/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/man/cmake_install.cmake")
  include("/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/tests/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

file(WRITE "/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/${CMAKE_INSTALL_MANIFEST}" "")
foreach(file ${CMAKE_INSTALL_MANIFEST_FILES})
  file(APPEND "/home/lancelot/git/nginx/third-lib/libressl-2.3.1/build/${CMAKE_INSTALL_MANIFEST}" "${file}\n")
endforeach()
