@echo off
del /F /S /Q .\docs\*
xcopy ".\TSA Client DocFX\_site\*" .\docs\ /E /C /F /Y
