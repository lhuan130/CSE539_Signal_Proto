#Helper commands for both clients and servers in the demo
import socket, datetime
target_port = 24601


##CLIENT##

msg_file = '_data/msg_log.txt'

#Register ID key, signed prekey, and one-time keys
def User_register(uname:str):
  #Note: registering won't delete existing messages but it will apply a reset to the user's message log
  with open(uname+msg_file,'a') as f:
    f.write(f"\n{str(datetime.datetime.now())}\n{uname} is now registering with the server. Any previous keys will not be useful.\n")

  #Registration procedure:
    #generate 3 sets of keys: identity, signed prekey, multiple one-time keys
    #use EdDSA for middle prekey signature
    #store necessary pieces to file system
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding, PrivateFormat, PublicFormat
  foldertag = f"{uname}_data/"

  #ID key
  print("Generating ID key")
  identity_key = Ed25519PrivateKey.generate()
  #keyList.append(identity_key)
  idkeyf = foldertag + f"{uname}_id_key.pem"
  with open(idkeyf,'wb') as f: f.write(identity_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
  print(len(identity_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)))

  #Long-term (signed) prekey
  from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
  print("Generating long-term prekey")
  signed_prekey = X25519PrivateKey.generate()
  #keyList.append(signed_prekey)
  print(len(signed_prekey.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)))
  print("Signing prekey with ID key")
  spk_pub_bytes = signed_prekey.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
  spk_sig = identity_key.sign(spk_pub_bytes)
  print(len(spk_sig))
  try: #verify sig generation
    identity_key.public_key().verify(spk_sig,spk_pub_bytes)
  except:
    print("Issue generating signature for signed prekey")
    return
  spkeyf = foldertag + f"{uname}_spkey.pem"
  spkeysigf = foldertag + f"{uname}_spksig.hx"
  with open(spkeyf,'wb') as f: f.write(signed_prekey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
  with open(spkeysigf,'w') as f: f.write(spk_sig.hex())

  otKeyList = dict()
  otkf1 = foldertag+f"{uname}_otk_"
  for i in range(5):
    otkf2 = f"{i}.pem"
    okey = X25519PrivateKey.generate()
    otKeyList[otkf2] = okey
    with open(otkf1+otkf2,'wb') as f: f.write(okey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))   

  #store message sent-and-received indexes (for client resync w/ server)
  with open(f"{uname}_data/"+"active_reg_sessionData.dat",'w') as f: f.write('0,0')

  print(f"Connecting to server to register {uname}.")
  # #Interact with server to register
  # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  #   s.connect(('127.0.0.1', target_port))
  #   #verify username
  #   s.send(uname.encode())
  #   msg = s.recv(128)
  #   print(msg.decode(),"\n")#You should get "User good."

  #   #instruction
  #   s.send(b'Register')
  #   msg = s.recv(128) #wait for "Ready." from server
  #   print(msg.decode(),"-> Msg from server.")

  #   #registration order: ID pubkey, signed pub-prekey, signature, one-time pubkeys
  #   #TODO id pubkey
    
  #   #TODO signed pub prekey

  #   #TODO sig
  #   for kname in otKeyList:
  #     otKeyList[kname].public_key().public_bytes()

  #   s.send(b'Done')
  #   s.close()
  

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

def handleRegistration(connection:socket,uname:str):
  connection.send(b'Ready.')
  #id pubkey
  #signed pubkey
  #signature
  #five otpubkeys
  connection.send(b'All received and processed.')

def handleListenerReq(connection:socket,uname:str):
  pass

def handleMsgSend(connection:socket,uname:str):
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
      handleRegistration(connection,username)
    if "Listening".equals(instr):
      handleListenerReq(connection,username)
    if "Sending".equals(instr):
      handleMsgSend(connection,username)
  except:
    connection.send(b'Error')
  finally:
    connection.close()
    return
