#Helper commands for both clients and servers in the demo


import socket, datetime, time
from os.path import exists
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding, PrivateFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


#some constants
target_port = 24601
otk_ct = 1 #This would normally be higher, given potential renegotiation needs, but for the demo it is just once
userSet = set(['alice','bob'])
targetSet = {'alice':'bob','bob':'alice'}
curveType = ec.SECP384R1() #See project writeup for the reason behind this decision
sig_alg, exc_alg, kdf_hash = ec.ECDSA(hashes.SHA256()), ec.ECDH(), hashes.SHA512


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
  identity_key = ec.generate_private_key(curveType)
  idk_raw = identity_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
  idkeyf = foldertag + f"{uname}_id_key.pem"
  with open(idkeyf,'wb') as f:
    f.write(idk_raw)

  #Long-term (signed) prekey
  print("Generating long-term prekey")
  signed_prekey = ec.generate_private_key(curveType)
  print("Signing prekey with ID key")
  spk_pub_bytes = signed_prekey.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
  spk_sig = identity_key.sign(spk_pub_bytes,sig_alg)
  print(len(spk_sig),spk_sig.hex())
  try: #verify sig generation
    identity_key.public_key().verify(spk_sig,spk_pub_bytes,sig_alg)
  except:
    print("Issue generating signature for signed prekey")
    return
  spkeyf = foldertag + f"{uname}_spkey.pem"
  spkeysigf = foldertag + f"{uname}_spksig.hx"
  with open(spkeyf,'wb') as f:
    f.write(signed_prekey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
  with open(spkeysigf,'wb') as f:
    f.write(spk_sig)

  #Group of one-time keys
  otKeyList = dict()
  otkf1 = foldertag+f"{uname}_otk_"
  for i in range(otk_ct):
    otkf2 = f"{i}.pem"
    okey = ec.generate_private_key(curveType)
    otKeyList[otkf2] = okey
    with open(otkf1+otkf2,'wb') as f:
      f.write(okey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))

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
    s.send(identity_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)) #id pubkey
    time.sleep(2)
    s.send(spk_pub_bytes) #signed pub prekey
    time.sleep(2)
    s.send(spk_sig) #prekey signature with idkey
    time.sleep(2)
    for kname in otKeyList: #otks
      s.send(otKeyList[kname].public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
      time.sleep(2)
    #end of interaction for registration
    s.send(b'Done')
    time.sleep(2)

def User_request(uname:str):
  #NOTE: the OTK generated here is also provided as the Ephemeral key during the 3DH
  
  foldertag = f"{uname}_data/"

  #Generate own IDkey and ephemeral key
  identity_key = ec.generate_private_key(curveType)
  idk_raw = identity_key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
  idkeyf = f"{uname}_id_key.pem"
  with open(idkeyf,'wb') as f:
    f.write(idk_raw)
  ekey = ec.generate_private_key(curveType)
  with open(foldertag+f"{uname}_ephkey.pem",'wb') as f:
    f.write(ekey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))

  print(f"Connecting to server as {uname} to request msg to {targetSet[uname]}.")
  #Interact with server to request connection with target
  #interleaved with socket handling, perform K1-4 generation and takes first message
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('127.0.0.1', target_port))
    #verify username
    s.send(uname.encode())
    msg = s.recv(32)
    print(msg.decode(),"\n")#You should get "User good."
    #instruction
    s.send(b'Connect') #this lets server know it's the "Step 2" from lecture
    time.sleep(2)

    #Send second IDkey and ephemeral key
    s.send(identity_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    time.sleep(2)
    s.send(ekey.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    print("Receiving public keys")
    #receive idpubkey
    idpubkey_bytes = s.recv(1024)
    t_idpk = load_pem_public_key(idpubkey_bytes)
    K1 = identity_key.exchange(exc_alg,t_idpk)
    K2 = ekey.exchange(exc_alg,t_idpk)
    #receive signature and signed pubprekey
    sig_ltpk_bytes = s.recv(1024)
    ltpk_bytes = s.recv(1024)
    t_ltpk = load_pem_public_key(ltpk_bytes)
    try:
      t_idpk.verify(sig_ltpk_bytes,ltpk_bytes,sig_alg)
    except:
      print("Signature failed")
    K3 = ekey.exchange(exc_alg,t_ltpk)
    #receive one-time pubkey
    otk_bytes = s.recv(1024)
    t_otpk = load_pem_public_key(otk_bytes)
    K4 = ekey.exchange(exc_alg,t_otpk)

    #generate encrypted key, send encrypted message
    print(len(K1),len(K2),len(K3),len(K4))
    keyconcat = bytearray()
    keyconcat.extend(K1)
    keyconcat.extend(K2)
    keyconcat.extend(K3)
    keyconcat.extend(K4)
    K = HKDFExpand(kdf_hash(),64,info=b'signaldemo').derive(keyconcat)
    print(K.hex())
    s.send(b'Proof 2nd client and server exchanged')#TOOD replace
  
  

  

  #HKDF -> generate keychains
  # from cryptography.hazmat.primitives.kdf.hkdf import HKDF
  # from cryptography.hazmat.primitives import hashes
  # hkdf_driver = HKDF(
  #   algorithm=kdf_alg,
  #   length=64,
  #   salt=None,
  #   info=b'handshake data',
  # )
# # Perform key derivation.
# derived_key = HKDF(
#   algorithm=kdf_alg,
#   length=64,
#   salt=None,
#   info=b'handshake data',
# ).derive(shared_key)


##SERVER##

def serverStartup():
  pass

def verifyUser(connection:socket):
  msg = connection.recv(16)
  uname = msg.decode()
  return True if uname in userSet else False, uname

def handleRegistration(connection:socket,uname:str):
  #During registration, we use the bytes sent and regenerate the public keys to check validity
  save_folder = f"server_data/{uname}_"

  #id pubkey
  msg = connection.recv(1024)
  print(len(msg))
  try:
    idkey = load_pem_public_key(msg)
    #save the identity public key's bytes
    with open(save_folder+"id_pub.pem",'wb') as f:
      f.write(msg)
  except Exception as e:
    print(e)
    print(f"Failed to load ID key for {uname}")
  #signed pubkey
  signedpk_bytes = connection.recv(1024)
  print(len(signedpk_bytes))
  try:
    ltspk = load_pem_public_key(signedpk_bytes)
    #save the long-term prekey's signed bytes
    with open(save_folder+"ltprek.pem",'wb') as f:
      f.write(signedpk_bytes)
  except Exception as e:
    print(e)
    print(f"Failed to load raw longterm public prekey for {uname}")
  #signature
  sig_bytes = connection.recv(1024)
  print(len(sig_bytes))
  try:
    #save signature
    with open(save_folder+"ltprek_sig.pem",'wb') as f:
      f.write(sig_bytes)
    idkey.verify(sig_bytes,signedpk_bytes,sig_alg)
  except Exception as e:
    print(e)
    print("Signature verification failed.")
  #otpubkey(s)
  for i in range(otk_ct):
    msg = connection.recv(1024)
    try:
      otpk = load_pem_public_key(msg)
      #save the onetime pkey bytes
      otknm = f"otk_{i}.pem"
      with open(save_folder+otknm,'wb') as f:
        f.write(msg)
    except:
      print(f"Failed to load a onetime public key for {uname}")
  #connection.send(b'All received and processed.')
  # #Receive last message
  # msg = connection.recv(128)
  # print(msg.encode())
  print("Registered recipient:",uname)


#sends public keys of registered client after receiving keys of applying client
def handleCon(connection:socket,uname:str):
  #Receive applying client's ID key and ephemeral key
  idkf, ephkf = f"server_data/{uname}_id_key.pem",f"server_data/{uname}_eph.pem"

  idk_bytes = connection.recv(1024)
  try:
    second_id = load_pem_public_key(idk_bytes)
    with open(idkf,'wb') as f:
      f.write(idkf)
  except Exception as e:
    print(e)
    print("Error loading ID key of client trying to handshake.")
  eph_bytes = connection.recv(1024)
  try:
    eph_pk = load_pem_public_key(idk_bytes)
    with open(ephkf,'wb') as f:
      f.write(ephkf)
  except Exception as e:
    print(e)
    print("Error loading ephemeral key of client trying to handshake.")
  time.sleep(2)
  #send public keys and ID-signature of registered client
  otherClient,targetList,sname = targetSet[uname],[],f"server_data/{otherClient}"
  targetList.append(sname+"_id_pub.pem")
  targetList.append(sname+"_ltprek_sig.pem")
  targetList.append(sname+"_ltprek.pem")
  targetList.append(sname+"_otk_0.pem")
  for filename in targetList:
    with open(filename,'rb') as f:
      connection.send(f.read())
    time.sleep(2)
  time.sleep(3)
  #Handle first encrypted message from applier to registerer
  firstmsg = connection.recv(1024)
  #TODO handle
  print(firstmsg.encode())#TODO replace


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


#per-connection activity tree on server side
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
  msg = connection.recv(128)
  instr = msg.decode()
  print(address, instr)
  try:
    if instr.startswith('Reg'):
      print(f"Handling new registration by {username}")
      handleRegistration(connection,username)
    if instr.startswith("Con"):
      print(f"Second client {username} is now connecting.")
      handleCon(connection,username)
    if instr.startswith('Asy'):
      print(f"Registered client {username} is performing their half of the DH.")
      handleListenerReq(connection,username)
    if instr.startswith('Sen'):
      print(f"Client {username} wants to send a message.")
      handleMsgSend(connection,username)
  except:
    connection.send(b'Error')
  finally:
    connection.close()
    return
