@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: ChromElevator Build System
:: =============================================================================

set "BUILD_DIR=build"
set "SRC_DIR=src"
set "LIBS_DIR=libs"
set "FINAL_EXE_NAME=chromelevator.exe"
set "PAYLOAD_DLL_NAME=chrome_decrypt.dll"
set "ENCRYPTOR_EXE_NAME=encryptor.exe"

:: Compiler Flags
set "CFLAGS_COMMON=/nologo /W3 /WX- /O1 /Os /MT /GS- /Gy /GL /GR- /Gw /Zc:threadSafeInit-"
set "CFLAGS_CPP=/std:c++17 /EHsc"
set "CFLAGS_SQLITE=/nologo /W0 /O1 /Os /MT /GS- /Gy /GL /DSQLITE_OMIT_LOAD_EXTENSION"

:: Linker Flags
set "LFLAGS_COMMON=/NOLOGO /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO"
set "LFLAGS_MERGE=/MERGE:.rdata=.text"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Parse command line arguments
if "%1"=="build_encryptor_only" goto :build_encryptor
if "%1"=="build_target_only" goto :build_target
if "%1"=="clean" goto :clean


:full_build
call :compile_sqlite
call :compile_payload
call :compile_encryptor
call :encrypt_payload
call :compile_resource
call :compile_injector
goto :done

:clean
echo Cleaning build directory...
if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
if exist "%FINAL_EXE_NAME%" del /q "%FINAL_EXE_NAME%"
echo Clean complete.
goto :eof

:build_encryptor
call :compile_sqlite
echo [1/2] Compiling ChaCha20...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\chacha20.cpp" /Fo"%BUILD_DIR%\chacha20.obj"
echo [2/2] Compiling Encryptor...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib
echo Encryptor built: %BUILD_DIR%\%ENCRYPTOR_EXE_NAME%
goto :eof

:build_target
call :compile_sqlite
call :compile_payload
call :encrypt_payload
call :compile_resource
call :compile_injector
goto :done

:: =============================================================================
:: BUILD SUBROUTINES
:: =============================================================================

:compile_sqlite
echo [1/6] Compiling SQLite3...
cl %CFLAGS_SQLITE% /c "%LIBS_DIR%\sqlite\sqlite3.c" /Fo"%BUILD_DIR%\sqlite3.obj" 2>nul
lib /NOLOGO /LTCG /OUT:"%BUILD_DIR%\sqlite3.lib" "%BUILD_DIR%\sqlite3.obj" >nul
goto :eof

:compile_payload
echo [2/6] Compiling Payload...
cl %CFLAGS_COMMON% /std:c++17 /EHs-c- /c "%SRC_DIR%\sys\bootstrap.cpp" /Fo"%BUILD_DIR%\bootstrap.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\payload_main.cpp" /Fo"%BUILD_DIR%\payload_main.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\com\elevator.cpp" /Fo"%BUILD_DIR%\elevator.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\pipe_client.cpp" /Fo"%BUILD_DIR%\pipe_client.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\data_extractor.cpp" /Fo"%BUILD_DIR%\data_extractor.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\aes_gcm.cpp" /Fo"%BUILD_DIR%\aes_gcm.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\chacha20.cpp" /Fo"%BUILD_DIR%\chacha20.obj"

link %LFLAGS_COMMON% %LFLAGS_MERGE% /DLL /OUT:"%BUILD_DIR%\%PAYLOAD_DLL_NAME%" ^
    "%BUILD_DIR%\payload_main.obj" "%BUILD_DIR%\bootstrap.obj" "%BUILD_DIR%\elevator.obj" ^
    "%BUILD_DIR%\pipe_client.obj" "%BUILD_DIR%\data_extractor.obj" "%BUILD_DIR%\aes_gcm.obj" ^
    "%BUILD_DIR%\chacha20.obj" "%BUILD_DIR%\sqlite3.lib" ^
    bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib crypt32.lib advapi32.lib kernel32.lib user32.lib libvcruntime.lib libucrt.lib
goto :eof

:compile_encryptor
echo [3/6] Compiling Encryptor...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib
goto :eof

:encrypt_payload
echo [4/6] Encrypting Payload...
"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" "%BUILD_DIR%\%PAYLOAD_DLL_NAME%" "%BUILD_DIR%\chrome_decrypt.enc"
goto :eof

:compile_resource
echo [5/6] Compiling Resource...
rc.exe /nologo /i "%BUILD_DIR%" /fo "%BUILD_DIR%\resource.res" "%SRC_DIR%\resource.rc"
goto :eof

:compile_injector
echo [6/6] Compiling Injector...
if "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
    armasm64.exe -nologo "%SRC_DIR%\sys\syscall_trampoline_arm64.asm" -o "%BUILD_DIR%\syscall_trampoline.obj"
) else (
    ml64.exe /nologo /c /Fo"%BUILD_DIR%\syscall_trampoline.obj" "%SRC_DIR%\sys\syscall_trampoline_x64.asm"
)

cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\injector\injector_main.cpp" /Fo"%BUILD_DIR%\injector_main.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\injector\browser_discovery.cpp" /Fo"%BUILD_DIR%\browser_discovery.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\injector\process_manager.cpp" /Fo"%BUILD_DIR%\process_manager.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\injector\pipe_server.cpp" /Fo"%BUILD_DIR%\pipe_server.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\injector\injector.cpp" /Fo"%BUILD_DIR%\injector.obj"
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\sys\internal_api.cpp" /Fo"%BUILD_DIR%\internal_api.obj"

link %LFLAGS_COMMON% %LFLAGS_MERGE% /OUT:".\%FINAL_EXE_NAME%" ^
    "%BUILD_DIR%\injector_main.obj" "%BUILD_DIR%\browser_discovery.obj" ^
    "%BUILD_DIR%\process_manager.obj" "%BUILD_DIR%\pipe_server.obj" ^
    "%BUILD_DIR%\injector.obj" "%BUILD_DIR%\internal_api.obj" ^
    "%BUILD_DIR%\chacha20.obj" "%BUILD_DIR%\syscall_trampoline.obj" ^
    "%BUILD_DIR%\resource.res" ^
    version.lib shell32.lib advapi32.lib user32.lib bcrypt.lib
goto :eof

:done
echo.
echo =============================================================================
echo [√] Build Complete: %FINAL_EXE_NAME%
for %%A in (".\%FINAL_EXE_NAME%") do echo [√] Binary Size: %%~zA bytes
echo =============================================================================
echo.
echo Cleaning up build artifacts...

:: Clean up intermediate files, keep only essential outputs
del /q "%BUILD_DIR%\*.obj" 2>nul
del /q "%BUILD_DIR%\*.lib" 2>nul
del /q "%BUILD_DIR%\*.exp" 2>nul
del /q "%BUILD_DIR%\*.res" 2>nul
del /q "%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" 2>nul

:: Clean up root directory artifacts
del /q "*.obj" 2>nul

echo [+] Cleaned intermediate object files
echo [+] Removed temporary artifacts
echo.
echo Build artifacts: %FINAL_EXE_NAME% + %BUILD_DIR%\chrome_decrypt.dll + %BUILD_DIR%\chrome_decrypt.enc
goto :eof
