#Helper commands for both clients and servers in the demo
import socket, datetime, time
from os.path import exists
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding, PrivateFormat

#some constants
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
  foldertag = f"{uname}_data/"

  #ID key
  print("Generating ID key")
  identity_key = Ed25519PrivateKey.generate() #a different type, because it has to SIGN the prekey's public bytes
  idkeyf = foldertag + f"{uname}_id_key.pem"
  with open(idkeyf,'wb') as f:
    f.write(identity_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))

  #Long-term (signed) prekey
  print("Generating long-term prekey")
  signed_prekey = X25519PrivateKey.generate()
  print("Signing prekey with ID key")
  spk_pub_bytes = signed_prekey.public_key().public_bytes_raw()
  spk_sig = identity_key.sign(spk_pub_bytes)
  #print(len(spk_sig),spk_sig.hex())
  try: #verify sig generation
    identity_key.public_key().verify(spk_sig,spk_pub_bytes)
  except:
    print("Issue generating signature for signed prekey")
    return
  spkeyf = foldertag + f"{uname}_spkey.pem"
  spkeysigf = foldertag + f"{uname}_spksig.hx"
  with open(spkeyf,'wb') as f:
    f.write(signed_prekey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
  with open(spkeysigf,'w') as f:
    f.write(spk_sig.hex())

  #Group of one-time keys
  otKeyList = dict()
  otkf1 = foldertag+f"{uname}_otk_"
  for i in range(5):
    otkf2 = f"{i}.pem"
    okey = X25519PrivateKey.generate()
    otKeyList[otkf2] = okey
    with open(otkf1+otkf2,'wb') as f:
      f.write(okey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))   

  #store message sent-and-received indexes (for client resync w/ server)
  with open(f"{uname}_data/"+"active_reg_sessionData.dat",'w') as f:
    f.write('0,0')

  print(f"Connecting to server to register {uname}.")
  #Interact with server to register
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('127.0.0.1', target_port))
    #verify username
    s.send(uname.encode())
    msg = s.recv(32)
    print(msg.decode(),"\n")#You should get "User good."
    #instruction
    s.send(b'Register')
    time.sleep(2)
    #registration order: ID pubkey, signed pub-prekey, signature, one-time pubkeys
    s.send(identity_key.public_key().public_bytes_raw()) #id pubkey
    time.sleep(2)
    s.send(spk_pub_bytes) #signed pub prekey
    time.sleep(2)
    s.send(spk_sig) #prekey signature with idkey
    time.sleep(2)
    for kname in otKeyList: #otks
      s.send(otKeyList[kname].public_key().public_bytes_raw())
      time.sleep(2)
    #end of interaction for registration
    s.send(b'Done')
    time.sleep(2)
    s.close()

def User_connect(uname:str):
  # Server ensures there is a potential connection
  # If there isn't a potential connection, this will return false.
  # If there is a connection to be made, this will return false after finishing the handshaking.
  # Otherwise, this will update the server with otks and return true
  pass

def User_handshakes(uname:str):
  pass

def User_resync(uname:str):
  pass

def User_msg_send(uname:str, msg:str):
  pass

  # from cryptography.hazmat.primitives.kdf.hkdf import HKDF
  # from cryptography.hazmat.primitives import hashes
  # hkdf_driver = HKDF(
  #   algorithm=hashes.SHA256(),
  #   length=32,
  #   salt=None,
  #   info=b'handshake data',
  # )


##SERVER##
userSet = set(['alice','bob'])
receiver_list = "server_data/new_rec_users.txt"
handshook_list = "server_data/ready_users.txt"

def verifyUser(connection:socket):
  msg = connection.recv(32)
  uname = msg.decode()
  return True if uname in userSet else False, uname

def handleRegistration(connection:socket,uname:str):
  #During registration, we use the bytes sent and regenerate the key objects to check validity
  save_folder = f"server_data/{uname}_"

  #id pubkey
  msg = connection.recv(128)
  try:
    idkey = Ed25519PublicKey.from_public_bytes(msg)
    #save the identity public key's bytes
    with open(save_folder+"id_pub.bytes",'wb') as f:
      f.write(msg)
  except:
    print(f"Failed to load ID key for {uname}")
  #signed pubkey
  signedpk_bytes = connection.recv(128)
  try:
    ltspk = X25519PublicKey.from_public_bytes(signedpk_bytes)
    #save the long-term prekey's signed bytes
    with open(save_folder+"ltprek.bytes",'wb') as f:
      f.write(signedpk_bytes)
  except:
    print(f"Failed to load raw longterm public prekey for {uname}")
  #signature
  sig_bytes = connection.recv(128)
  try:
    idkey.verify(signature=sig_bytes,data=ltspk.public_bytes_raw())
    #save signature
    with open(save_folder+"ltprek_sig.bytes",'wb') as f:
      f.write(sig_bytes)
  except Exception as e:
    print(e)
    print("Signature verification failed.")
  #five otpubkeys
  for i in range(5):
    msg = connection.recv(128)
    try:
      otpk = X25519PublicKey.from_public_bytes(msg)
      #save the onetime pkey bytes
      otknm = f"otk_{i}.bytes"
      with open(save_folder+otknm,'wb') as f:
        f.write(msg)
    except:
      print(f"Failed to load a onetime public key for {uname}")
  #connection.send(b'All received and processed.')

  #Receive last message
  msg = connection.recv(128)
  print(msg.encode())

  #Note registerer in file so that other registering party is connected
  with open(receiver_list,'a') as f:
    f.write(f"{uname}\n")
  return

def handleCon(connection:socket,uname:str):
  pass

  #Receive last message
  msg = connection.recv(256)
  print(msg.encode())

def handleListenerReq(connection:socket,uname:str):
  pass

  #Receive last message
  msg = connection.recv(256)
  print(msg.encode())

def handleMsgSend(connection:socket,uname:str):
  pass

  #Receive last message
  msg = connection.recv(256)
  print(msg.encode())

#base connection process on server side
def handleClient(connection:socket, address):
  print("CONNECTION FROM:", str(address)) # display client address
  #verify that the connection is an expected user
  verified, username = verifyUser(connection)
  if verified:
    print(f"Verified {username}")
    connection.send(b'User good.')
  else:
    print("Invalid user detected. Shutting down connection.")
    connection.close()
    return
  
  #Now the user will have received a "User good." message and can make their request
  msg = connection.recv(256)
  instr = msg.decode()
  print(address, instr)
  try:
    if instr.startswith('Reg'):
      print(f"Handling new registration by {username}")
      handleRegistration(connection,username)
    if instr.startswith("Con"):
      print(f"Checking if {username} has a chat session.")
      handleCon(connection,username)
    if instr.startswith('Lis'):
      print(f"Client {username} is updating their state with the server.")
      handleListenerReq(connection,username)
    if instr.startswith('Sen'):
      print(f"Client {username} wants to send a message.")
      handleMsgSend(connection,username)
  except:
    connection.send(b'Error')
  finally:
    connection.close()
    return





# # Perform key derivation.
# derived_key = HKDF(
#   algorithm=hashes.SHA256(),
#   length=32,
#   salt=None,
#   info=b'handshake data',
# ).derive(shared_key)