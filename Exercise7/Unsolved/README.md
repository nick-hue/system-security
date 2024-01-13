ΗΡΥ 413 Assignment: 7  
AM: 2019030190 Nikolaos Angelidis   
AM: 2019030201 Chrysiis Manoudaki  

We created a simple script in python to create the input for the buffer in order exploit the readString function to spawn a shell.  
Through the GDB debugger we got the machine code for the code snippet that would return such a shell, we also got the memory address that the global variable 'Name' is stored, the address is '0x80dacc0' that was printed with the use of the command 'p &Name' after the program was run.

#### In order to run our program: 
    (python3 exploit.py; cat) | ./Greeter  

We pipe into the Greeter program our custom made input. If we don't run the exploit as so, the file descriptor of the shell closes before we can actually use the shell, to fix that we use the cat command in the same line to keep it running.

After the above command is executed press enter once and a terminal shell will have spawned and you can run any command as usual (ls, id, whoami, etc).  