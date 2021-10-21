echo. & echo Misc. stuff (hosts, dns flushing, etc...)
ipconfig /flushdns >> nul 2>&1
REM Wasn't sure how CP would check it, so I just copied the default hosts file in.
attrib -r -s %systemroot%\system32\drivers\etc\hosts >> nul 2>&1 
REM Covering all my bases with these switches
xcopy %cd%\scriptResources\hosts %systemroot%\system32\drivers\etc /Q /R /H /Y >> nul 2>&1
REM Power configuration (require password on wakeup)
powercfg -SETDCVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MIN SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg -SETDCVALUEINDEX SCHEME_MAX SUB_NONE CONSOLELOCK 1
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1

echo AIF,M3U,TXT,M4A,MID,MP3,MPA,RA,WAV,WMA,3G2,3GP,ASF,ASX,AVI,FLV,M4V,MOV,MP4,MPG,RM,SRT,SWF,VOB,WMV,BMP,GIF,JPG,PNG,PSD,TIF,YUV,GAM,SAV,TORRENT,WEBM,FLV,OG
