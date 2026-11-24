@echo off
setlocal DisableDelayedExpansion

rem Excellent Books plugin launcher for Windows: finds a Node runtime and runs start.mjs.
set "EXCELLENT_BOOKS_LAUNCHER=%~dp0start.mjs"
rem Codex passes no arguments; only the launcher's own check flag is forwarded, never raw text.
set "EXCELLENT_BOOKS_FLAG="
if "%~1"=="--install-only" set "EXCELLENT_BOOKS_FLAG=--install-only"
set "EXCELLENT_BOOKS_NODE="

rem This process waits for Node and must not keep the installed plugin folder locked
rem (Codex replaces that folder on an update), so it moves to the system folder first.
if defined SystemRoot (cd /d "%SystemRoot%\System32") else (cd /d "%~d0\")
if errorlevel 1 (
  echo Excellent Books could not start: no safe Windows working directory. 1>&2
  exit /b 1
)

rem The probe order of OpenAI's own Codex plugins: the runtimes Codex ships first, the PATH last.
rem WindowsApps can expose a Node path that exists but cannot be executed, so relocated
rem user-writable runtimes come before the packaged paths. A candidate counts only when its path is
rem absolute (its full form is the path itself) and it is a file, not a folder.
if defined LOCALAPPDATA for %%R in ("%LOCALAPPDATA%") do if /i "%%~fR"=="%%~R" for /d %%D in ("%%~R\OpenAI\Codex\runtimes\cua_node\*") do for %%P in ("%%~fD\bin\node.exe") do if not defined EXCELLENT_BOOKS_NODE if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined XDG_CACHE_HOME for %%R in ("%XDG_CACHE_HOME%") do if /i "%%~fR"=="%%~R" for %%P in ("%%~R\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe") do if not defined EXCELLENT_BOOKS_NODE if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined USERPROFILE for %%R in ("%USERPROFILE%") do if /i "%%~fR"=="%%~R" for %%P in ("%%~R\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe") do if not defined EXCELLENT_BOOKS_NODE if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined CODEX_MCP_NODE_PATH for %%P in ("%CODEX_MCP_NODE_PATH%") do if not defined EXCELLENT_BOOKS_NODE if /i "%%~fP"=="%%~P" if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined CODEX_BROWSER_USE_NODE_PATH for %%P in ("%CODEX_BROWSER_USE_NODE_PATH%") do if not defined EXCELLENT_BOOKS_NODE if /i "%%~fP"=="%%~P" if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined CODEX_ELECTRON_RESOURCES_PATH for %%R in ("%CODEX_ELECTRON_RESOURCES_PATH%") do if /i "%%~fR"=="%%~R" for %%P in ("%%~R\cua_node\bin\node.exe") do if not defined EXCELLENT_BOOKS_NODE if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
if defined CODEX_CLI_PATH for %%I in ("%CODEX_CLI_PATH%") do if /i "%%~fI"=="%%~I" for %%P in ("%%~dpIcua_node\bin\node.exe") do if not defined EXCELLENT_BOOKS_NODE if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"
rem The PATH last, resolved to a full path: $PATH: keeps where.exe from searching the current folder.
if not defined EXCELLENT_BOOKS_NODE for /f "delims=" %%N in ('where $PATH:node.exe 2^>nul') do for %%P in ("%%N") do if not defined EXCELLENT_BOOKS_NODE if /i "%%~fP"=="%%~P" if exist "%%~P" if not exist "%%~P\*" set "EXCELLENT_BOOKS_NODE=%%~P"

if not defined EXCELLENT_BOOKS_NODE (
  echo Excellent Books could not find a Node runtime. Reinstall or update Codex, or set CODEX_MCP_NODE_PATH to an executable Node runtime. 1>&2
  exit /b 127
)
"%EXCELLENT_BOOKS_NODE%" "%EXCELLENT_BOOKS_LAUNCHER%" %EXCELLENT_BOOKS_FLAG% & exit
