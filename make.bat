@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: =                            CONFIGURATION                                  =
:: =============================================================================
set "BUILD_DIR=build"
set "SRC_DIR=src"
set "LIBS_DIR=libs"
set "FINAL_EXE_NAME=chromelevator.exe"
set "PAYLOAD_DLL_NAME=chrome_decrypt.dll"
set "ENCRYPTOR_EXE_NAME=encryptor.exe"
set "VERBOSE=1"

:: Compiler and Linker Flags (Optimized for size and stealth)
set "CFLAGS_COMMON=/nologo /W3 /O1 /MT /GS- /Gy /GL"
set "CFLAGS_CPP_ONLY=/EHsc /std:c++17"
set "LFLAGS_COMMON=/link /NOLOGO /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /EMITPOGOPHASEINFO"
set "LFLAGS_STRIP=/PDBALTPATH:none /NOCOFFGRPINFO"

:: =============================================================================
:: =                                  COLORS                                   =
:: =============================================================================
for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "C_RESET=%ESC%[0m"
set "C_RED=%ESC%[91m"
set "C_GREEN=%ESC%[92m"
set "C_YELLOW=%ESC%[93m"
set "C_CYAN=%ESC%[96m"
set "C_GRAY=%ESC%[90m"

:: =============================================================================
:: =                               ENTRY POINT                                 =
:: =============================================================================

:: Use a robust, linear GOTO-based flow control to avoid all parser quirks.
if /i "%~1" == "build_encryptor_only" goto :main_build_encryptor
if /i "%~1" == "build_target_only" goto :main_build_target

:: Default action if no argument is provided
goto :main_full_build


:: =============================================================================
:: =                              MAIN LOGIC                                   =
:: =============================================================================

:main_full_build
    call :display_banner
    call :check_environment
    if %errorlevel% neq 0 goto :HandleExit
    call :pre_build_setup
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_sqlite
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_payload
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_encryptor
    if %errorlevel% neq 0 goto :HandleExit
    call :encrypt_payload
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_resource
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_injector
    if %errorlevel% neq 0 goto :HandleExit
    call :post_build_summary
    goto :HandleExit

:main_build_encryptor
    call :display_banner
    call :check_environment
    if %errorlevel% neq 0 goto :HandleExit
    call :pre_build_setup
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_encryptor
    goto :HandleExit

:main_build_target
    call :display_banner
    call :check_environment
    if %errorlevel% neq 0 goto :HandleExit
    call :pre_build_setup_no_clean_encryptor
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_sqlite
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_payload
    if %errorlevel% neq 0 goto :HandleExit
    call :encrypt_payload
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_resource
    if %errorlevel% neq 0 goto :HandleExit
    call :compile_injector
    if %errorlevel% neq 0 goto :HandleExit
    call :post_build_summary
    goto :HandleExit


:: =============================================================================
:: =                          EXIT HANDLING                                    =
:: =============================================================================

:HandleExit
set "EXIT_CODE=%errorlevel%"
if %EXIT_CODE% neq 0 (
    call :log_error "Build failed. Cleaning up intermediate files."
    call :cleanup >nul 2>&1
    goto :EndScript
)

:: Success path
if /i "%~1" == "build_encryptor_only" (
    rem If we only built the tool, exit silently.
    goto :EndScript
)

:: For any other successful build, print the success message.
call :log_info "Build successful. Final artifacts are ready."

:EndScript
endlocal
exit /b %EXIT_CODE%


:: =============================================================================
:: =                             BUILD SUBROUTINES                             =
:: =============================================================================

:display_banner
    echo %C_CYAN%--------------------------------------------------%C_RESET%
    echo %C_CYAN%^|          Chrome Injector Build Script          ^|%C_RESET%
    echo %C_CYAN%--------------------------------------------------%C_RESET%
    echo.
goto :eof

:check_environment
    call :log_info "Verifying build environment..."
    if not defined DevEnvDir (
        call :log_error "This script must be run from a Developer Command Prompt for VS."
        exit /b 1
    )
    call :log_success "Developer environment detected."
    call :log_info "Target Architecture: %C_YELLOW%%VSCMD_ARG_TGT_ARCH%%C_RESET%"
    echo.
goto :eof

:pre_build_setup
    call :log_info "Performing pre-build setup..."
    call :cleanup
    call :log_info "  - Creating fresh build directory: %BUILD_DIR%"
    mkdir "%BUILD_DIR%"
    if %errorlevel% neq 0 (
        call :log_error "Failed to create build directory."
        exit /b 1
    )
    call :log_success "Setup complete."
    echo.
goto :eof

:pre_build_setup_no_clean_encryptor
    call :log_info "Performing pre-build setup..."
    if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
    call :log_success "Setup complete."
    echo.
goto :eof

:compile_sqlite
    call :log_step "[1/6] Compiling SQLite3 Library"
    set "CMD_COMPILE=cl %CFLAGS_COMMON% /c %LIBS_DIR%\sqlite\sqlite3.c /Fo"%BUILD_DIR%\sqlite3.obj""
    set "CMD_LINK=lib /NOLOGO /OUT:"%BUILD_DIR%\sqlite3.lib" "%BUILD_DIR%\sqlite3.obj""
    call :run_command "%CMD_COMPILE%" "  - Compiling C object file..."
    if %errorlevel% neq 0 exit /b 1
    call :run_command "%CMD_LINK%" "  - Creating static library..."
    if %errorlevel% neq 0 exit /b 1
    call :log_success "SQLite3 library built successfully."
    echo.
goto :eof

:compile_payload
    call :log_step "[2/6] Compiling Payload DLL (%PAYLOAD_DLL_NAME%)"
    set "CMD_C=cl %CFLAGS_COMMON% /c %SRC_DIR%\reflective_loader.c /Fo"%BUILD_DIR%\reflective_loader.obj""
    call :run_command "%CMD_C%" "  - Compiling C file (reflective_loader.c)..."
    if %errorlevel% neq 0 exit /b 11

    set "CMD_CPP=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% /I%LIBS_DIR%\sqlite /c %SRC_DIR%\chrome_decrypt.cpp /Fo"%BUILD_DIR%\chrome_decrypt.obj""
    call :run_command "%CMD_CPP%" "  - Compiling C++ file (chrome_decrypt.cpp)..."
    if %errorlevel% neq 0 exit /b 1
    
    set "CMD_LINK=link /NOLOGO /DLL /OUT:"%BUILD_DIR%\%PAYLOAD_DLL_NAME%" "%BUILD_DIR%\chrome_decrypt.obj" "%BUILD_DIR%\reflective_loader.obj" "%BUILD_DIR%\sqlite3.lib" bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib /IMPLIB:"%BUILD_DIR%\chrome_decrypt.lib""
    call :run_command "%CMD_LINK%" "  - Linking objects into DLL..."
    if %errorlevel% neq 0 exit /b 1
    
    call :log_success "Payload DLL compiled successfully."
    echo.
goto :eof

:compile_encryptor
    call :log_step "[3/6] Compiling Encryption Utility (%ENCRYPTOR_EXE_NAME%)"
    set "CMD=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% /I%LIBS_DIR%\chacha %SRC_DIR%\encryptor.cpp /Fo"%BUILD_DIR%\encryptor.obj" %LFLAGS_COMMON% /OUT:"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%""
    call :run_command "%CMD%" "  - Compiling and linking..."
    if %errorlevel% neq 0 exit /b 1
    call :log_success "Encryptor utility compiled successfully."
    echo.
goto :eof

:encrypt_payload
    call :log_step "[4/6] Encrypting Payload DLL"
    set "CMD=%BUILD_DIR%\%ENCRYPTOR_EXE_NAME% %BUILD_DIR%\%PAYLOAD_DLL_NAME% %BUILD_DIR%\chrome_decrypt.enc"
    call :run_command "%CMD%" "  - Running encryption process..."
    if %errorlevel% neq 0 exit /b 1
    call :log_success "Payload encrypted to chrome_decrypt.enc."
    echo.
goto :eof

:compile_resource
    call :log_step "[5/6] Compiling Resource File"
    set "CMD=rc.exe /i "%BUILD_DIR%" /fo "%BUILD_DIR%\resource.res" %SRC_DIR%\resource.rc"
    call :run_command "%CMD%" "  - Compiling .rc to .res..."
    if %errorlevel% neq 0 exit /b 1
    call :log_success "Resource file compiled successfully."
    echo.
goto :eof

:compile_injector
    call :log_step "[6/6] Compiling Final Injector (%FINAL_EXE_NAME%)"
    if "%VSCMD_ARG_TGT_ARCH%"=="x64" (
        set "TRAMpoline_SRC=%SRC_DIR%\syscall_trampoline_x64.asm"
        set "TRAMPOLINE_OBJ=%BUILD_DIR%\syscall_trampoline_x64.obj"
        set "ASM_CMD=ml64.exe /c /Fo"!TRAMPOLINE_OBJ!" "!TRAMPOLINE_SRC!""
    ) else if "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
        set "TRAMpoline_SRC=%SRC_DIR%\syscall_trampoline_arm64.asm"
        set "TRAMPOLINE_OBJ=%BUILD_DIR%\syscall_trampoline_arm64.obj"
        set "ASM_CMD=armasm64.exe -nologo "!TRAMPOLINE_SRC!" -o "!TRAMPOLINE_OBJ!""
    ) else (
        call :log_error "Unsupported target architecture: %VSCMD_ARG_TGT_ARCH%. Only x64 and arm64 are supported."
        exit /b 1
    )
    call :run_command "!ASM_CMD!" "  - Assembling syscall trampoline (%VSCMD_ARG_TGT_ARCH%)..."
    if %errorlevel% neq 0 exit /b 1
    set "CMD_COMPILE_INJECTOR_SRC=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% /I%LIBS_DIR%\chacha /c %SRC_DIR%\chrome_inject.cpp /Fo"%BUILD_DIR%\chrome_inject.obj""
    call :run_command "!CMD_COMPILE_INJECTOR_SRC!" "  - Compiling C++ source (chrome_inject.cpp)..."
    if %errorlevel% neq 0 exit /b 1
    
    set "CMD_COMPILE_SYSCALLS_SRC=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% /c %SRC_DIR%\syscalls.cpp /Fo"%BUILD_DIR%\syscalls.obj""
    call :run_command "!CMD_COMPILE_SYSCALLS_SRC!" "  - Compiling C++ source (syscalls.cpp)..."
    if %errorlevel% neq 0 exit /b 1
    
    set "CMD_COMPILE_OBFUSCATION_SRC=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% /c %SRC_DIR%\syscalls_obfuscation.cpp /Fo"%BUILD_DIR%\syscalls_obfuscation.obj""
    call :run_command "!CMD_COMPILE_OBFUSCATION_SRC!" "  - Compiling C++ source (syscalls_obfuscation.cpp)..."
    if %errorlevel% neq 0 exit /b 1
    
    set "CMD_LINK_FINAL=cl %CFLAGS_COMMON% %CFLAGS_CPP_ONLY% "%BUILD_DIR%\chrome_inject.obj" "%BUILD_DIR%\syscalls.obj" "%BUILD_DIR%\syscalls_obfuscation.obj" !TRAMPOLINE_OBJ! "%BUILD_DIR%\resource.res" version.lib shell32.lib %LFLAGS_COMMON% %LFLAGS_STRIP% /OUT:".\%FINAL_EXE_NAME%""
    call :run_command "!CMD_LINK_FINAL!" "  - Linking final executable..."
    if %errorlevel% neq 0 exit /b 1
    call :log_success "Final injector built successfully."
    echo.
goto :eof

:post_build_summary
    echo %C_CYAN%--------------------------------------------------%C_RESET%
    echo %C_CYAN%^|                 BUILD SUCCESSFUL               ^|%C_RESET%
    echo %C_CYAN%--------------------------------------------------%C_RESET%
    echo.
    echo   %C_YELLOW%Final Executable:%C_RESET% .\%FINAL_EXE_NAME%
    echo.
goto :eof


:: =============================================================================
:: =                           HELPER SUBROUTINES                              =
:: =============================================================================

:run_command
    set "command_to_run=%~1"
    set "message=%~2"
    call :log_info "%message%"
    if %VERBOSE%==1 (
        echo %C_GRAY%!command_to_run!%C_RESET%
        !command_to_run!
    ) else (
        !command_to_run! >nul 2>nul
    )

    if %errorlevel% neq 0 (
        call :log_error "Previous step failed. Halting build."
        exit /b 1
    )
goto :eof

:cleanup
    if exist "%BUILD_DIR%\" rmdir /s /q "%BUILD_DIR%"
    if exist "%FINAL_EXE_NAME%" del "%FINAL_EXE_NAME%" > nul 2>&1
goto :eof

:log_step
    echo %C_YELLOW%-- %~1 %C_YELLOW%------------------------------------------------%C_RESET%
goto :eof

:log_info
    echo %C_GRAY%[INFO]%C_RESET% %~1
goto :eof

:log_success
    echo %C_GREEN%[ OK ]%C_RESET% %~1
goto :eof

:log_error
    echo %C_RED%[FAIL]%C_RESET% %~1
goto :eof
