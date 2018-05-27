@echo off

set PROJ_DIR=%1
set OUT_DIR=%2
set PATH_PACKER=%OUT_DIR%\packer.exe
set PATH_PAYLOAD=%OUT_DIR%\payload.dll
set PATH_HEADER_TARGET=%PROJ_DIR%\launcher\payload.h
set PATH_HEADER_TEMP=%PATH_HEADER_TARGET%.tmp


%PATH_PACKER% %PATH_PAYLOAD% %PATH_HEADER_TEMP%

fc %PATH_HEADER_TEMP% %PATH_HEADER_TARGET% >NUL 2>NUL && goto _no_change || goto _gen_header

:_gen_header
move /Y %PATH_HEADER_TEMP% %PATH_HEADER_TARGET%
echo A newer version of 'payload.h' was generated.
goto _end

:_no_change
del %PATH_HEADER_TEMP%
echo No need to update 'payload.h'.

:_end
