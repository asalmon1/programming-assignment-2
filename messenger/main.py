from cryptography.hazmat.primitives.asymmetric import ec

from messenger import MessengerServer
from messenger import MessengerClient

def error(s):
  print("=== ERROR: " + s)

print("Initializing Server")
server_sign_sk = ec.generate_private_key(ec.SECP256R1())
server_enc_sk = ec.generate_private_key(ec.SECP256R1())
server = MessengerServer(server_sign_sk, server_enc_sk)

server_sign_pk = server_sign_sk.public_key()
server_enc_pk = server_enc_sk.public_key()

print("Initializing Users")
alice = MessengerClient("alice", server_sign_pk, server_enc_pk)
bob = MessengerClient("bob", server_sign_pk, server_enc_pk)
carol = MessengerClient("carol", server_sign_pk, server_enc_pk)

print("Generating Certs")
certA = alice.generateCertificate()
certB = bob.generateCertificate()
certC = carol.generateCertificate()

print("Signing Certs")
sigA = server.signCert(certA)
sigB = server.signCert(certB)
sigC = server.signCert(certC)

print("Distributing Certs")
try:
    alice.receiveCertificate(certB, sigB)
    alice.receiveCertificate(certC, sigC)
    bob.receiveCertificate(certA, sigA)
    bob.receiveCertificate(certC, sigC)
    carol.receiveCertificate(certA, sigA)
    carol.receiveCertificate(certB, sigB)
except:
    error("certificate verification issue")

print("Testing incorrect cert issuance")
mallory = MessengerClient("mallory", server_sign_pk, server_enc_pk)
certM = mallory.generateCertificate()
try:
    alice.receiveCertificate(certM, sigC)
except:
    print("successfully detected bad signature!")
else:
    error("accepted certificate with incorrect signature")

print("Testing Reporting")
content = "inappropriate message contents"
reportPT, reportCT = alice.report("Bob", content)
decryptedReport = server.decryptReport(reportCT)
if decryptedReport != reportPT:
    error("report did not decrypt properly")
    print(reportPT)
    print(decryptedReport)
else:
    print("Reporting test successful!")

print("Testing a conversation")
header, ct = alice.sendMessage("bob", "Hi Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Hi Bob!":
    error(f"Message 1 was not decrypted correctly. Should have been 'Hi Bob!' but got '{msg}'")

header, ct = alice.sendMessage("bob", "Hi again Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Hi again Bob!":
    error(f"Message 2 was not decrypted correctly. Should have been 'Hi again Bob!' but got '{msg}'")

header, ct = bob.sendMessage("alice", "Hey Alice!")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Hey Alice!":
    error(f"Message 3 was not decrypted correctly. Should have been 'Hey Alice!' but got '{msg}'")

header, ct = bob.sendMessage("alice", "Can't talk now")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Can't talk now":
    error(f"Message 4 was not decrypted correctly. Should have been 'Can't talk now' but got '{msg}'")

header, ct = bob.sendMessage("alice", "Started the homework too late :(")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Started the homework too late :(":
    error(f"Message 5 was not decrypted correctly. Should have been 'Started the homework too late :(' but got '{msg}'")

header, ct = alice.sendMessage("bob", "Ok, bye Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Ok, bye Bob!":
    error(f"Message 6  was not decrypted correctly. Should have been 'Ok, bye Bob!' but got '{msg}'")

header, ct = bob.sendMessage("alice", "I'll remember to start early next time!")
msg = alice.receiveMessage("bob", header, ct)
if msg != "I'll remember to start early next time!":
    error(f"Message 7 was not decrypted correctly. Should have been 'I'll remember to start early next time!' but got '{msg}'")

print("conversation completed!")


print("Testing handling an incorrect message")

h, c = alice.sendMessage("bob", "malformed message test")
m = bob.receiveMessage("alice", h, ct)
if m != None:
    error("didn't reject incorrect message")
else:
    print("success!")


print("Testing complete")
