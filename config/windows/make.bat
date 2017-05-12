@echo off
del /q /s build dist 2> NUL
rmdir /q /s build dist 2> NUL

set PYTHONPATH=.

C:\Python27\python.exe ..\pyinstaller\pyinstaller.py --hidden-import artifacts --hidden-import IPython --onedir tools\preg.py

set PYTHONPATH=
