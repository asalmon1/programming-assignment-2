import os
import pickle
import string
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from panel import state





def serialize_public_key(pk):
    return pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(data):
    return serialization.load_der_public_key(data)

def generate_dh_keypair():
    return ec.generate_private_key(ec.SECP256R1())

def kdf_rk(rk, dh_out):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b'ratchet key derivation',
    )
    out = hkdf.derive(dh_out)
    return out[:32], out[32:]

def kdf_ck(ck):
    h1 = hmac.HMAC(ck, hashes.SHA256())
    h1.update(b'\x01')
    mk = h1.finalize()
    h2 = hmac.HMAC(ck, hashes.SHA256())
    h2.update(b'\x02')
    ck_new = h2.finalize()
    return mk, ck_new

def generate_header(dh_pair, pn, n):
    dh_pair_serialized = serialize_public_key(dh_pair.public_key())
    header = {
        'dh': dh_pair_serialized,
        'pn': pn,
        'n': n
        }
    return pickle.dumps(header)

def ae_encrypt(mk, plaintext, associated_data):
    aesgcm = AESGCM(mk)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
    return nonce + ct

def ae_decrypt(mk, ciphertext, associated_data):
    aesgcm = AESGCM(mk)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    pt = aesgcm.decrypt(nonce, ct, associated_data)
    return pt.decode()

def dh(priv, pub):
    return priv.exchange(ec.ECDH(), pub)

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        signature = self.server_signing_key.sign(
            cert,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    def generateCertificate(self):
        self.own_dh_keypair = generate_dh_keypair()
        certificate = {
            'name': self.name,
            'pk': serialize_public_key(self.own_dh_keypair.public_key())
        }
        return pickle.dumps(certificate)

    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(
                signature,
                certificate,
                ec.ECDSA(hashes.SHA256())
            )
        except:
            raise Exception("certificate signature verification failed")
        cert_data = pickle.loads(certificate)
        self.certs[cert_data['name']] = cert_data

    def initializeConnection(self, name):
        if name not in self.certs:
            raise Exception("No certificate found for user: " + name)
        
        state = {}

        state['DHs'] = generate_dh_keypair()
        state['DHr'] = deserialize_public_key(self.certs[name]['pk'])

        dh_sk = dh(state['DHs'], state['DHr'])

        rk, cks = kdf_rk(b'\x00' * 32, dh_sk)
        state['RK'] = rk
        state['CKs'] = cks

        state['CKr'] = None
        state['Ns'] = 0
        state['Nr'] = 0
        state['PN'] = 0

        self.conns[name] = state

    def sendMessage(self, name, message):
        if name not in self.conns:
            self.initializeConnection(name)
        
        state = self.conns[name]

        mk, state['CKs'] = kdf_ck(state['CKs'])
        Ns = state['Ns']
        state['Ns'] += 1

        header = generate_header(state['DHs'], state['PN'], Ns)
        return header, ae_encrypt(mk, message, header)


    def receiveMessage(self, name, header, ciphertext):
        if name not in self.conns:
            self.initializeConnection(name)

        state = self.conns[name]

        try:
            header_obj = pickle.loads(header)
            header_dh = header_obj['dh']
        except Exception:
            return None

        mk = self.ratchetReceiveKey(state, header_dh)

        try:
            plaintext = ae_decrypt(mk, ciphertext, header)
            return plaintext
        except Exception:
            return None


    def ratchetReceiveKey(self, state, header_dh):
        header_dh_key = deserialize_public_key(header_dh)
        
        if serialize_public_key(state['DHr']) != header_dh:
            self.dHRatchet(state, header_dh_key)
        

        state['CKr'], mk = kdf_ck(state['CKr'])
        state['Nr'] += 1
        return mk


    def dHRatchet(self, state, header_dh_key):
        state['PN'] = state['Ns']
        state['Ns'] = 0
        state['Nr'] = 0
        state['DHr'] = header_dh_key
        
        state['RK'], state['CKr'] = kdf_rk(state['RK'], dh(state['DHs'], state['DHr']))
        state['DHs'] = generate_dh_keypair()
        state['RK'], state['CKs'] = kdf_rk(state['RK'], dh(state['DHs'], state['DHr']))


    def report(self, name, message):
        raise Exception("not implemented!")
        return
