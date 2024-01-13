
The "-z execstack" flag: allows the c programm to be run with machine code in it 

Through the GDB debugger we got the machine code for the code snippet that would return such a shell. 
also we got the memory address that the global variable 'Name' is stored, the address is '0x80dacc0' with the command 'p &Name' after the program was run

(python3 exploit.py; cat) | ./Greeter 

If we don't run the exploit as so the file descriptor of the shell closes before we can actually use the shell, so we use the cat command in the same line.