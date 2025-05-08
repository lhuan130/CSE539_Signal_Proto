#Client
from commands import *

# main() -> Procedure:
# A - take user input as an integer. If not valid, retry. If valid, do and exit.
#   1 - One party registers triple public keys to server.
#   2 - Other party receives them and provides their necessary keys.
#   3 - First registered party
#       - if there was a new connection request, receive 3XDH data and build ratchet
#       - get any messages on the server for this client
#       - provide X one-time-keys until server has 5 available
#   3 - Use existing key stores and encrypt a single message to the server for the other client.
def main():
  name = (input("Client name (enter 'alice' or 'bob';\nbob should be registered first for the demo) >- ")).lower()
  if name not in userSet:
    print("Valid user (for two-person exchange demo) please.")
    return
  print("Enter 0 to quit.")
  print("Enter 1 to register with the server. This will erase any existing keys on server or local under this name.")
  print("Enter 2 to perform the message request interaction (async 3DH).")
  print("Enter 3 to perform the async 3DH using the registered user and to receive the first message.")
  print("  Please note that 2,3 are distinct interactions and do not overlap.")
  while True:
    try:
      userInt = input("Your entry: ")
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
    #Provide two request keys and collect first person's handshake keys
    User_request(name)
  
  if dataInt == 3:
    #The registered user now has to do the shared KDF and receive the first message
    User_listen(name)
  
#  if dataInt == 4:
    #Either party can now send messages to the other
    #This operation opens with a check for existing messages
#    User_send(name)

main()
