#Helper commands for both clients and servers in the demo


import socket, datetime, time, os
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding, PrivateFormat, PublicFormat, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#some constants
target_host = '127.0.0.1'
target_port = 24601
otk_ct = 1 #This would normally be higher, given potential renegotiation needs, but for the demo it is just once
userSet = set(['alice','bob'])
targetSet = {'alice':'bob','bob':'alice'}
curveType = ec.SECP384R1() #See project writeup for the reason behind this decision
sig_alg = ec.ECDSA(hashes.SHA256())
exc_alg = ec.ECDH()
kdf_hash = hashes.SHA256 #done like this as hash instances need to be initialized independently
firstMsgData = b'Alice would like to connect with Bob.'

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
  #print(len(spk_sig),spk_sig.hex())
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
    s.connect((target_host, target_port))
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
    for kname in otKeyList: #otk(s)
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
  with open(foldertag+f"{uname}_id_key.pem",'wb') as f:
    f.write(idk_raw)
  ekey = ec.generate_private_key(curveType)
  with open(foldertag+f"{uname}_ephkey.pem",'wb') as f:
    f.write(ekey.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))

  #Interact with server to request connection with target
  #interleaved with socket handling, perform K1-4 generation and takes first message
  print(f"Connecting to server as {uname} to request msg to {targetSet[uname]}.")
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((target_host, target_port))
    #verify username
    s.send(uname.encode())
    msg = s.recv(32)
    print(msg.decode(),"\n")#You should get "User good."
    #instruction
    s.send(b'Connect') #this lets server know it's the "Step 2" from lecture
    time.sleep(2)

    #Send second IDkey and ephemeral key
    print("Sending identity & ephemeral keys.")
    s.send(identity_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    time.sleep(2)
    s.send(ekey.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    time.sleep(2)
    print("Receiving public keys")
    #receive idpubkey
    idpubkey_bytes = s.recv(1024)
    #print(idpubkey_bytes)
    t_idpk = load_pem_public_key(idpubkey_bytes)
    #receive signature and signed pubprekey
    sig_ltpk_bytes = s.recv(1024)
    ltpk_bytes = s.recv(1024)
    #print(ltpk_bytes)
    t_ltpk = load_pem_public_key(ltpk_bytes)
    try:
      t_idpk.verify(sig_ltpk_bytes,ltpk_bytes,sig_alg)
    except:
      print("Signature failed")
    #receive one-time pubkey
    otk_bytes = s.recv(1024)
    #print(otk_bytes)
    t_otpk = load_pem_public_key(otk_bytes)

    #generate encrypted key, send encrypted message
    K1 = identity_key.exchange(exc_alg,t_ltpk)
    K2 = ekey.exchange(exc_alg,t_idpk)
    K3 = ekey.exchange(exc_alg,t_ltpk)
    K4 = ekey.exchange(exc_alg,t_otpk)
    #print(len(K1),len(K2),len(K3),len(K4))
    keyconcat = bytearray()
    keyconcat.extend(K1)
    keyconcat.extend(K2)
    keyconcat.extend(K3)
    keyconcat.extend(K4)
    K = bytearray(HKDFExpand(kdf_hash(),64,info=b'signaldemo').derive(bytes(keyconcat)))
    Ka,Kb = bytes(K[:32]),bytes(K[32:])

    #Demo display of KDF output
    print(Ka.hex())#use for first message
    print(Kb.hex())#use for KDF

    #encrypted message
    encmsg = bytearray()
    nonce = os.urandom(12)#AESGCM Nonce
    assoc_data = bytearray()#specifically requires PEM bytes of sender idpubkey, then receiver idpubkey, for first message
    assoc_data.extend(identity_key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    assoc_data.extend(t_idpk.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    assoc_data = bytes(assoc_data)
    ciphertext = AESGCM(Ka).encrypt(nonce,firstMsgData,assoc_data)

    #construct and send
    encmsg.extend(nonce)
    encmsg.extend(ciphertext)
    s.send(encmsg)
    time.sleep(2)
    s.send(b'Confirming 2nd client has sent message to registerer.')#TOOD replace
    time.sleep(2)
  
  #store associated data and KDF data for this user
  with open(f"{uname}_data/kdf0.hx",'wb') as f:
    f.write(bytes(K))
  with open(f"{uname}_data/assoc.hx",'wb') as f:
    f.write(assoc_data)


def User_listen(uname:str):
  #Open local private keys
  foldertag = f"{uname}_data/"
  idkf = f"{uname}_id_key.pem"
  spkf = f"{uname}_spkey.pem"
  otkf = f"{uname}_otk_0.pem"
  with open(foldertag+idkf,'rb') as f:
    ikb_b = f.read()
    ikb = load_pem_private_key(ikb_b,None)
  with open(foldertag+spkf,'rb') as f:
    spkb_b = f.read()
    spkb = load_pem_private_key(spkb_b,None)
  with open(foldertag+otkf,'rb') as f:
    opkb_b = f.read()
    opkb = load_pem_private_key(opkb_b,None)
  print(f"{uname}'s keys loaded. Sizes:",len(ikb_b),len(spkb_b),len(opkb_b))

  # collect other party's keys and first ciphertext
  K1,K2,K3,K4 = None,None,None,None
  print(f"Connecting to server as {uname} to receive message from {targetSet[uname]}.")
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((target_host, target_port))
    #verify username
    s.send(uname.encode())
    msg = s.recv(32)
    print(msg.decode(),"\n")#You should get "User good."
    #instruction
    s.send(b'Async') #this lets server know it's the "Step 3" from lecture
    #receive other idpk
    id_pka_bytes = s.recv(1024)
    #print(id_pka_bytes)
    #print(id_pka_bytes.decode())
    try:
      id_pka = load_pem_public_key(id_pka_bytes)
      print("Id loaded")
    except Exception as e:
      print(e)
      print("Failure to load other party's identity pkey")
    #receive eph_pk
    eph_pka_bytes = s.recv(1024)
    #print(id_pka_bytes.decode())
    try:
      eph_pka = load_pem_public_key(eph_pka_bytes)
      print("Eph loaded")
    except Exception as e:
      print(e)
      print("Failure to load other party's ephemeral pkey")
    #receive ciphertext bytes
    ct = s.recv(512)
    print("Ciphertext received")
    #send received confirmation
    s.send(b'All received.')
    time.sleep(1)
  
  try:
    K1 = spkb.exchange(exc_alg,id_pka)
    K2 = ikb.exchange(exc_alg,eph_pka)
    K3 = spkb.exchange(exc_alg,eph_pka)
    K4 = opkb.exchange(exc_alg,eph_pka)
  except Exception as e:
    print(e)
    print("Error performing DH on registered user's side.")
  if K1 is None or K2 is None or K3 is None or K4 is None:
    print("Failure to perform handshake; a key was not loaded somewhere.")
    return
  # check registerer's half of the 3DH, generate encrypted key, send encrypted message
  keyconcat = bytearray()
  keyconcat.extend(K1)
  keyconcat.extend(K2)
  keyconcat.extend(K3)
  keyconcat.extend(K4)
  K = bytearray(HKDFExpand(kdf_hash(),64,info=b'signaldemo').derive(bytes(keyconcat)))
  Ka,Kb = bytes(K[:32]),bytes(K[32:])

  #Format: 12-byte nonce, AES
  ct = bytearray(ct)
  nonce,cdata = ct[:12],ct[12:]
  assoc_data = bytearray()#specifically requires PEM bytes of sender idpubkey, then receiver idpubkey, for first message
  assoc_data.extend(id_pka.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
  assoc_data.extend(ikb.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
  assoc_data = bytes(assoc_data)
  plaintext = AESGCM(Ka).decrypt(nonce,cdata,assoc_data)
  
  #construct and send
  print("Expected first message printed next to received first message below.")
  print(firstMsgData.decode())
  print(plaintext.decode())

  #Demo display of KDF output
  print()
  print(Ka.hex())#use for first message
  print(Kb.hex())#use for future KDF

  #store associated data and KDF data for this user
  with open(f"{uname}_data/kdf0.hx",'wb') as f:
    f.write(bytes(K))
  with open(f"{uname}_data/assoc.hx",'wb') as f:
    f.write(assoc_data)



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
  #print(len(msg))
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
  #print(len(signedpk_bytes))
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
  #print(len(sig_bytes))
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


#Party 2 passes first message after exchanging keys
def handleCon(connection:socket,uname:str):
  #Receive applying client's ID key and ephemeral key
  idkf, ephkf = f"server_data/{uname}_id_key.pem",f"server_data/{uname}_eph.pem"

  idk_bytes = (connection.recv(1024))
  try:
    second_id = load_pem_public_key(idk_bytes)
    with open(idkf,'wb') as f:
      f.write(idk_bytes)
    print("Identity key loaded and saved.")
  except Exception as e:
    print(e)
    print("Error loading ID key of client trying to handshake.")
  eph_bytes = (connection.recv(1024))
  try:
    eph_pk = load_pem_public_key(eph_bytes)
    with open(ephkf,'wb') as f:
      f.write(eph_bytes)
    print("Ephemeral key loaded and saved.")
  except Exception as e:
    print(e)
    print("Error loading ephemeral key of client trying to handshake.")
  time.sleep(2)
  #send public keys and ID-signature of registered client
  target = targetSet[uname]
  print(target)
  filename = f"server_data/{target}_id_pub.pem"
  with open(filename,'r') as f:
    print(f"Opening {filename} and sending to {uname}.")
    fbyt = f.read()
    #print(fbyt)
    connection.send(fbyt.encode())
  time.sleep(2)
  filename = f"server_data/{target}_ltprek_sig.pem"
  with open(filename,'rb') as f:
    print(f"Opening {filename} and sending to {uname}.")
    fbyt = f.read()
    #print(fbyt)
    connection.send(fbyt)
  time.sleep(2)
  filename = f"server_data/{target}_ltprek.pem"
  with open(filename,'r') as f:
    print(f"Opening {filename} and sending to {uname}.")
    fbyt = f.read()
    #print(fbyt)
    connection.send(fbyt.encode())
  time.sleep(2)
  filename = f"server_data/{target}_otk_0.pem"
  with open(filename,'r') as f:
    print(f"Opening {filename} and sending to {uname}.")
    fbyt = f.read()
    #print(fbyt)
    connection.send(fbyt.encode())
  time.sleep(2)

  #Handle first encrypted message from applier to registerer
  firstmsg = connection.recv(1024)
  print(firstmsg)
  with open("server_data/first_msg.dat",'wb') as f:
    f.write(firstmsg)
  confirm = connection.recv(128)
  print(confirm.encode())


def handleListenerReq(connection:socket,uname:str):
  #load values and send over network, slight delays for control
  target = targetSet[uname]
  print(f"Sending {target}'s two keys back to first registered user.")
  
  #send other party's idk
  with open(f"server_data/{target}_id_key.pem",'r') as f:
    idpk = f.read()
  connection.send(idpk.encode())
  print(f"{target} public idkey sent.")
  time.sleep(1)

  #send other party's ephk
  with open(f"server_data/{target}_eph.pem",'r') as f:
    ephpk = f.read()
  connection.send(ephpk.encode())
  print(f"{target} public ephemeral key sent.")
  time.sleep(1)
  
  with open("server_data/first_msg.dat",'rb') as f:
    firstmsg = f.read()
  #send cipher bytes
  connection.send(firstmsg)
  print("First message ciphertext sent.")
  time.sleep(1)

  #Receive confirmation from registerer client as receipt
  msg = connection.recv(32)
  print(msg.decode())
  time.sleep(1)


def handleMsgSend(connection:socket,uname:str):
  pass


#per-connection activity tree on server side
def handleClient(connection:socket, address):
  print("CONNECTION FROM:", str(address)) # display client address
  #verify that the connection is an expected user
  verified, username = verifyUser(connection)
  if not verified:
    print("Invalid user detected. Shutting down connection.")
    connection.close()
    return
  time.sleep(1)
  print(f"Verified {username}")
  connection.send(b'User good.')
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
