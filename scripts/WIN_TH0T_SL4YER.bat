@echo off

Rem this script is still being worked on won't be fully operational until the end of the summer - Suyash

net accounts /lockoutduration:30
net accounts /lockoutthreshold:6
net accounts /lockoutwindow:30

net accounts /minpwlen:8
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /uniquepw:3

Rem This script is owned by C0DE R3D, developed by Suyash Ojha
