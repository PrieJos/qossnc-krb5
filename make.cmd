@echo off

setlocal
title QOSSNC_KRB5

rem #########################
rem Development Tools
rem #########################

rem ### Visual Studio 2012
set VS_HOME=C:\Program Files (x86)\Microsoft Visual Studio 11.0
set VS110COMNTOOLS=%VS_HOME%\Common7\Tools
set VC_BIN32=%VS_HOME%\VC\bin
set VC_BIN64=%VS_HOME%\VC\bin\amd64
set VC_INC=%VS_HOME%\VC\include;%VS_HOME%\VC\atlmfc\include
set VC_LIB32=%VS_HOME%\VC\lib;%VS_HOME%\VC\atlmfc\lib
set VC_LIB64=%VS_HOME%\VC\lib\amd64;%VS_HOME%\VC\atlmfc\lib\amd64
rem ###

rem ### Windows SDK Windows 8
set WINSDK_HOME=C:\Program Files (x86)\Windows Kits\8.0
set WINSDK_BIN32=%WINSDK_HOME%\bin\x86
set WINSDK_BIN64=%WINSDK_HOME%\bin\x64
set WINSDK_INC=%WINSDK_HOME%\include\um;%WINSDK_HOME%\include\shared
set WINSDK_LIB32=%WINSDK_HOME%\lib\win8\um\x86
set WINSDK_LIB64=%WINSDK_HOME%\lib\win8\um\x64
rem ###
rem #########################

rem #########################
rem Common Settings
rem #########################
set INCLUDE=%VC_INC%;%WINSDK_INC%
if %CPU%. == AMD64. goto :do_make_64
if %CPU%. == i386. goto :do_make_32
if %CPU%. == . goto :do_make_32
rem #########################

rem #########################
rem x64
rem #########################
:do_make_64
set PATH=%VC_BIN64%;%VS_HOME%\Common7\IDE;%WINSDK_BIN64%;C:\Windows\system32;C:\Windows
set LIB=%VC_LIB64%;%WINSDK_LIB64%
rem set LIBPATH=%VC_LIB64%
goto :do_make_any
rem #########################

rem #########################
rem x86
rem #########################
:do_make_32
set PATH=%VC_BIN32%;%VS_HOME%\Common7\IDE;%WINSDK_BIN32%;C:\Windows\system32;C:\Windows
set LIB=%VC_LIB32%;%WINSDK_LIB32%
rem set LIBPATH=%VC_LIB32%
goto :do_make_any
rem #########################

:do_make_any
nmake /F Makefile.win clean
nmake /F Makefile.win all
rem #########################
