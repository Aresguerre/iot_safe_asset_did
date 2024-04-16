
import base64

from iot_safe_crypto import get_public_key 
from iot_safe_crypto import verify
from iot_safe_crypto import get_signature
from iot_safe_crypto import initialize_iot_safe
from iot_safe_crypto import iot_safe_cleanup

from utils import *


def base64_url_encode(string):
    encoded = base64.urlsafe_b64encode(string.encode('utf-8')).decode('utf-8')
    return encoded.rstrip("=")

def create_token(message):

    initialize_iot_safe()

    header:JWTHeader = JWTHeader(
        alg='ES256',
        typ='JWT'
    )
    encoded_header:str = base64_url_encode(header.to_json())
    encoded_body:str = base64_url_encode(message)
    payload:str = "".join([encoded_header, '.', encoded_body])

    result = get_signature(payload)

    encoded_signature:str = base64.urlsafe_b64encode(result).decode("ascii").rstrip("=")
    
    jwt_token:str = "".join([encoded_header, '.', encoded_body, '.', encoded_signature])
    
    iot_safe_cleanup()
    
    return jwt_token

def verify_token(jwt:str) -> bool:
    
    initialize_iot_safe()

    sig_start_index = jwt.rindex('.')
    encoded_payload = jwt[:sig_start_index]
    encoded_signature = jwt[sig_start_index+1:]

    padding = 4 - (len(encoded_signature)%4)
    encoded_signature_w_padding = encoded_signature + (("=") * padding)
    signature = base64.urlsafe_b64decode(encoded_signature_w_padding.encode('utf-8'))

    verified = verify(encoded_payload, signature)

    iot_safe_cleanup()
    
    return verified

def pub2pem():

    initialize_iot_safe()

    public_key_pem = bytearray.fromhex('3059301306072A8648CE3D020106082A8648CE3D03010703420004'+get_public_key()[2:])
    public_key_pem = '-----BEGIN PUBLIC KEY-----\n' + \
        base64.b64encode(public_key_pem).decode('ascii') + \
        '\n-----END PUBLIC KEY-----'
    
    iot_safe_cleanup()

    return public_key_pem

if __name__ == "__main__":
    # asset_DID = 'did:ethr:0xf4a96dd3E1437D5a32A9F41b23897202F363B0a'
    # claim_data:ClaimData = ClaimData(
    #         blockNumber=999999999999
    #     )
    # claim:PublicClaim = PublicClaim(
    #     claimData=claim_data,
    #     iss=asset_DID
    # )
    # payload:str = claim.to_json()
    # jwt_identity_token = create_token(asset_DID)
    # print(jwt_identity_token)
    print(pub2pem())
