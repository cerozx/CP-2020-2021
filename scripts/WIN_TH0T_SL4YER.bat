@echo off

REM this script is still being worked on won't be fully operational until the end of the summer - Suyash

REM Basic password policies there are one or two of them you gotta do manually

net accounts /lockoutduration:30
net accounts /lockoutthreshold:6
net accounts /lockoutwindow:30

net accounts /minpwlen:10
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /uniquepw:3

REM Disables guest

net userguest /active:no

REM Enables the firewall

netsh advfirewall set allprofiles state on

REM Disables Telnet I am still working on this one

REM  This script is owned by C0DE BLUE, developed by Suyash Ojha
