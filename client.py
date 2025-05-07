#Client
from commands import *

# main() -> Procedure:
# A - take user input as an integer. If not valid, retry. If valid, do and exit.
#   1 - Register long-term public keys to server.
#   2 - Update with server
#       - if there was a new connection request, receive 3XDH data and build ratchet
#       - get any messages on the server for this client
#       - provide X one-time-keys until server has 5 available
#   3 - Use existing key stores and encrypt a single message to the server for the other client.
def main():
  name = (input("Client name (enter 'alice' or 'bob';\nbob should be registered first for the demo):  ")).lower()
  if name not in set(['alice','bob']):
    print("Valid user (for two-person exchange demo) please.")
    return
  print("Enter 0 to quit.")
  print("Enter 1 to register with the server. This will erase any existing keys on server or local under this name.")
  print("Enter 2 to use your existing registration to check your messages.")
  print("Enter 3 to send a message with your existing registration.")
  print("  Please note that 2,3 are distinct and do not overlap.")
  while True:
    try:
      userInt = input("Your entry:")
      dataInt = int(userInt)
      if dataInt < 0 or dataInt > 3:
        print("Try again.")
        continue
      break
    except:
      print("Try again.")

  if dataInt == 0:
    print(f"Closing client for {name}")

  if dataInt == 1:
    #Run register command and finish
    User_register(name)
  
  if dataInt == 2:
    #Resync with server using existing client's files
    User_resync(name)
  
  if dataInt == 3:
    #Send a message with your current keyset.
    print("Enter the message you wish to send.")
    print("Unfortuantely, I can only handle text.")
    print("Hitting enter will send your message.")
    User_msg_send(name, input())

# # Perform key derivation.
# derived_key = HKDF(
#   algorithm=hashes.SHA256(),
#   length=32,
#   salt=None,
#   info=b'handshake data',
# ).derive(shared_key)

main()
