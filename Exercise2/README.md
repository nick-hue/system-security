By running the Makefile with: m
ake clean 
make 
make run

16 files will have been generated, each with varying levels of access enabled or disabled. To execute the tasks associated with the second phase: ./acmonitor -m or ./acmonitor -i

Whenever a user does actions according to files, logs will be created about the accessing of the file at the log file (file_logging.log). When creating a new file the access code is 0. When opening a file the access code is 1. When writing to a file the access code is 2. The log file also documents instances where a user lacks access to a file. By running the acmonitor program, you can monitor suspicious user activity and determine the count of accesses and modifications made by a user to a specific file.
