@echo off
echo Setting the lockout policy
net accounts /lockoutduration:30
net accounts /lockoutthreshold:6
net accounts /lockoutwindow:30

echo Setting pasword policies
net accounts /minpwlen:8
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /uniquepw:3
