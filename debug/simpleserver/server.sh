#!/bin/sh


#while true; 
#   echo -e "HTTP/1.1 200 OK\n\n<h1>Title</h1>$(date)" \
#  | nc -l -k -p 8080 -q 1;
#  nc -l -k -p 8080 -q 1 | cat - | grep -o '{...\+}';
#do true; done
echo -e "HTTP/1.1 200 OK\n\n<h1>Title</h1>$(date)" | nc -l -p 8888 -q 0 > clientkeycmd.bin;

echo "TESTING"
exit

#while true; do 
#  echo -e "HTTP/1.1 200 OK\n\n<h1>Title</h1>$(date)" | netcat -l -k -p 8888 -q 0;
#  nc -l -k -p 8888 -q 0 | cat - | grep -o '{...\+}'; 
  
   echo -e "HTTP/1.1 200 OK\n\n<h1>Title</h1>$(date)" | nc -l -k -p 8888 -q 0; 
#done