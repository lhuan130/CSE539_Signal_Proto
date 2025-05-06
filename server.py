#Server system

from commands import *

print("Initializing Server...")
print("PLEASE NOTE: You can only have up to 5 messages to a recipient stored asynchronously on the server, for one-time-key reasons.")

#Listen for registrations and messaging

import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind(('', 24601))
  s.listen(2)
  print("READY TO RECEIVE") #Run client1.py OR client2.py at this point
  i = 0
  #wait process
  while True:
    c,addr = s.accept()
    i += 1
    print("Session",i,"started.")
    handleClient(c,addr)
