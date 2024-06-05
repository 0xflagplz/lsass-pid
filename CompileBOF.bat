@ECHO OFF

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc getlsapid-svc.c
move /y getlsapid-svc.obj getlsapid.o

