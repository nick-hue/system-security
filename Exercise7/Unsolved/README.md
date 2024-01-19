ΗΡΥ 413 Assignment: 7  
AM: 2019030190 Nikolaos Angelidis   
AM: 2019030201 Chrysiis Manoudaki  

We created a simple script in python to create the input for the buffer in order exploit the readString function to spawn a shell.  
#### The machine code for the spawning of a terminal shell was found online, we tested that it works as intended with the following commands.
    gcc test_shell.c -o shell -fno-stack-protector -z execstack -no-pie -m32
    ./shell
we also got the memory address that the global variable 'Name', the address is '0x80dacc0' that was printed with the use of the command 'p &Name' after the program was executed in the debugger.

#### In order to run our program: 
    (python3 exploit.py; cat) | ./Greeter  

We pipe into the Greeter program our custom made input. If we don't run the exploit as so, the file descriptor of the shell closes before we can actually use the shell, to fix that we use the cat command in the same line to keep it running.

After the above command is executed press enter once and a terminal shell will have spawned and you can run any command as usual (ls, id, whoami, etc).  

## Bonus 
#### In order to run our program: 
    (python3 exploit_bonus.py; cat) | ./SecGreeter

#### Use the following command to disable ASLR:  
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space 

We have to find the memory addresses for the following primitives:
- system
- exit  

#### To find their memory addresses, run the program with gdb:   
    gdb -q ./SecGreeter  
Put a breakpoint in main with "b main" and run the program with "r", later we used the "p system" and "p exit" commands to print the corresponding memory addresses.  
At last we have to find the memory address that the value "/bin/sh" in the libc library is stored. We do that by executing the command "info proc map" and getting the memory range in which the libc library is stored. Later we use the command "find _start_memory_address_, _end_memory_address_,"/bin/sh"".    

Now that we have all the parts for the exploit, we construct a payload with Python like so:

payload = _padding_ + _system_address_ + _exit_address_ + _bin_sh_address_ 

Providing the above payload to the program spawns a terminal shell after "Enter" is pressed once. To verify the correct function of our spawned terminal, you can run any command as usual (ls, id, whoami, etc) as before.
