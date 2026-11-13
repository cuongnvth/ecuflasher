@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "BUMP=%~1"

echo ==================================================
echo   ECUFlasher Build Script (Optimized Size)
echo ==================================================
echo.

python -c "import struct,sys; assert struct.calcsize('P')*8==64, 'Need 64-bit'" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 64-bit required.
    exit /b 1
)

echo [1/8] Installing dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if errorlevel 1 exit /b 1

echo [2/8] Checking vendor DLLs and UPX...
set "MISSING=0"
if not exist "vendor\vector\vxlapi64.dll" set "MISSING=1"
if not exist "vendor\pcan\PCANBasic.dll" set "MISSING=1"
if "%MISSING%"=="1" echo [WARN] Missing vendor DLLs. Build continues.
where upx >nul 2>&1 && echo [INFO] UPX found, it will compress safe files. || echo [INFO] UPX not found, extra compression skipped. Optional: https://upx.github.io

echo [3/8] Updating version...
if not "%BUMP%"=="" (
    python build_version.py --bump %BUMP%
    if errorlevel 1 exit /b 1
)
python build_version.py --build
if errorlevel 1 exit /b 1
for /f "usebackq delims=" %%v in (`python build_version.py --print`) do set "APP_VERSION=%%v"

echo [4/8] Cleaning...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [5/8] Building seed-key bridge (32-bit)...
py -3-32 -c "import struct;assert struct.calcsize('P')*8==32" >nul 2>&1
if errorlevel 1 (
    echo [WARN] Python 32-bit not found. Bridge will not be built.
    goto :build_main
)
py -3-32 -m pip install pyinstaller --quiet
py -3-32 -m PyInstaller --clean --noconfirm build32.spec
if errorlevel 1 goto :build_main
echo [OK] Bridge32 built.

:build_main

echo [6/8] Building main EXE (64-bit)...
pyinstaller --clean --noconfirm build.spec
if errorlevel 1 exit /b 1

echo [7/8] Assembling...
if exist dist\ECUFlasher32 (
    if not exist dist\ECUFlasher\bridge32 mkdir dist\ECUFlasher\bridge32
    xcopy /E /I /Y /Q dist\ECUFlasher32\* dist\ECUFlasher\bridge32\ >nul
    rmdir /s /q dist\ECUFlasher32
)

if exist assets\THIRD_PARTY_NOTICES.txt copy /Y /Q assets\THIRD_PARTY_NOTICES.txt dist\ECUFlasher\ >nul
if exist README.md copy /Y /Q README.md dist\ECUFlasher\ >nul
python build_version.py --print-full > dist\ECUFlasher\VERSION.txt

echo [8/8] Packing and reporting size...
powershell -NoProfile -Command "$s=(Get-ChildItem 'dist\ECUFlasher' -Recurse -File | Measure-Object Length -Sum).Sum/1MB; Write-Host ('[SIZE] Folder: {0:N1} MB' -f $s)"
where 7z >nul 2>&1 && (7z a -t7z -mx=9 -bso0 -bsp0 dist\ECUFlasher_v%APP_VERSION%.7z dist\ECUFlasher) || (powershell -NoProfile -Command "Compress-Archive -Path 'dist\ECUFlasher' -DestinationPath 'dist\ECUFlasher_v%APP_VERSION%.zip' -Force")
if exist dist\ECUFlasher_v%APP_VERSION%.7z powershell -NoProfile -Command "Write-Host ('[SIZE] dist\ECUFlasher_v%APP_VERSION%.7z: {0:N1} MB' -f ((Get-Item 'dist\ECUFlasher_v%APP_VERSION%.7z').Length/1MB))"
if exist dist\ECUFlasher_v%APP_VERSION%.zip powershell -NoProfile -Command "Write-Host ('[SIZE] dist\ECUFlasher_v%APP_VERSION%.zip: {0:N1} MB' -f ((Get-Item 'dist\ECUFlasher_v%APP_VERSION%.zip').Length/1MB))"

echo.
echo ==================================================
echo   BUILD COMPLETE - version %APP_VERSION%
echo ==================================================
echo   Output: dist\ECUFlasher\ECUFlasher.exe
echo.
endlocal
