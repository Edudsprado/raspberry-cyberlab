@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 goto usar_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 goto usar_python
py -3 "%~dp0scripts\run_tests.py" %*
exit /b %errorlevel%

:usar_python
where python >nul 2>nul
if errorlevel 1 goto sem_python
python "%~dp0scripts\run_tests.py" %*
exit /b %errorlevel%

:sem_python
echo Python nao encontrado. Instale Python 3.10 ou superior.
exit /b 1
