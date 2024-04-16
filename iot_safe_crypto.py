from ctypes import *
import base64

libiot_safe_crypto = cdll.LoadLibrary('./libcryptosafe.so')

c_ubyte_p = POINTER(c_ubyte)
initialize_iot_safe = libiot_safe_crypto.initialize

iot_safe_get_public_key = libiot_safe_crypto.read_public_key
iot_safe_get_public_key.restype = (c_void_p)

iot_safe_get_signature = libiot_safe_crypto.compute_signature
iot_safe_get_signature.argtypes = [c_ubyte_p, c_uint32]
iot_safe_get_signature.restype = (c_ubyte_p)

iot_safe_verify = libiot_safe_crypto.verify_signature
iot_safe_verify.argtypes = [c_ubyte_p, c_uint32, c_ubyte_p]
iot_safe_verify.restype = (c_uint16)

iot_safe_free = libiot_safe_crypto.free_p

iot_safe_cleanup = libiot_safe_crypto.cleanup


def get_signature(message)->bytes:
    #initialize context iot safe
    #initialize_iot_safe()
    #string to c char pointer
    payload = (c_ubyte * len(message)).from_buffer(bytearray(message.encode("utf-8")))
    #hash in SHA256 and sign with ECDSA
    signature_p=iot_safe_get_signature(payload,sizeof(payload))
    #cast and get value of signature pointer
    #signature = cast(signature_p, c_char_p).value
    signature = string_at(signature_p,64)
    #free dynamically created memory
    iot_safe_free(signature_p)
    #str_sign = signature.decode('utf-8')
    return signature

def get_public_key()->str:
    #get public key for respective label
    ret = iot_safe_get_public_key()
    #cast to get value of public key
    result = cast(ret, c_char_p).value
    #free dynamically created memory
    iot_safe_free(ret)
    pub = result.decode('utf-8').upper()
    print(pub)
    #returns value with compression code
    return pub

def verify(message, signature:bytes)->bool:

    payload = (c_ubyte * len(message)).from_buffer(bytearray(message.encode("utf-8")))
    sig = (c_ubyte * len(signature)).from_buffer(bytearray(signature))
    ver = iot_safe_verify(payload, sizeof(payload), sig)
    if(ver==0x9000):
        return True

    return False
