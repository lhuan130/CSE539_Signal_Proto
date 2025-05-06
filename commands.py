#Helper commands for both clients and servers in the demo
import socket
target_port = 24601


##CLIENT##

#Register ID key, signed prekey, and one-time keys
def User_register(uname:str):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('127.0.0.1', target_port))

    #Registration procedure:
      #generate 3 sets of keys: identity, signed prekey, multiple one-time keys
      #use EdDSA for middle prekey signature
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    # keyList = []
    # identity_key = X25519PrivateKey.generate()
    # signed_prekey = X25519PrivateKey.generate()
    # keyList.append(identity_key)
    # keyList.append(signed_prekey)
    # for i in range(5):
    #   keyList.append(X25519PrivateKey.generate())

    #TODO generate signature for signed_prekey

    #store message sent-and-received indexes (for client resync w/ server)
    with open(f"{uname}_data/"+"active_reg_sessionData.txt",'w') as f: f.write('0,0')

    s.send(b'Done')
    s.close()
  

def User_resync(uname:str):
  pass

def User_msg_send(uname:str, msg:str):
  from cryptography.hazmat.primitives.kdf.hkdf import HKDF
  from cryptography.hazmat.primitives import hashes
  hkdf_driver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
  )



##SERVER##

userSet = set(['alice','bob'])
def verifyUser(connection:socket):
  msg = connection.recv(1024)
  uname = msg.decode()
  return True if uname in userSet else False, uname

def handleRegistration(connection:socket):
  pass

def handleListenerReq(connection:socket):
  pass

#base connection process on server side
def handleClient(connection:socket, address):
  print("CONNECTION FROM:", str(address)) # display client address
  #verify that the connection is an expected user
  verified, username = verifyUser(connection)
  if verified:
    print("User verified:",username)
    connection.send(b'User good.')
  else:
    print("Invalid user detected. Shutting down connection.")
    connection.close()
    return
  
  #Now the user will have received a "User good." message and can make their request
  msg = connection.recv(1024)
  instr = msg.decode()
  print(address, instr)
  try:
    if "Register".equals(instr):
      handleRegistration(connection)
    if "Listening".equals(instr):
      handleListenerReq(connection)
  except:
    connection.send(b'Error')
    connection.close()
    return

  #display any future received messages until blank or "Done" received; free socket at that point
  while msg:
    if len(msg) == 0:
      connection.close()
      break
    instr = msg.decode()
    print(instr)
    if (instr.equals("Done")):
      connection.close()
      break
    msg = connection.recv(1024)