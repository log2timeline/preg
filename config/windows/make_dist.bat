@echo off
del /q /s dist\preg 2> NUL

rmdir /q /s dist\preg 2> NUL

mkdir dist\preg
mkdir dist\preg\data
mkdir dist\preg\licenses

xcopy /q /y ACKNOWLEDGEMENTS dist\preg
xcopy /q /y AUTHORS dist\preg
xcopy /q /y LICENSE dist\preg
xcopy /q /y README dist\preg
xcopy /q /y config\licenses\* dist\preg\licenses

xcopy /q /y /s dist\preg\* dist\preg
xcopy /q /y data\* dist\preg\data
