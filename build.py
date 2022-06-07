import subprocess
s = subprocess.getstatusoutput(f'make build_go')
print(s)