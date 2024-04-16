
import asyncio
import os
import random
import threading
import queue
import pendulum

from dataclasses import dataclass
from dataclasses_json import DataClassJsonMixin

from jsonschema import validate

from py_dotenv import read_dotenv

from ew_dsb_client_lib.dsb_client_lib import DSBClient
from ew_dsb_client_lib.message.dtos.operation_message_dto import PublishMessageDto
from ew_dsb_client_lib.auth.entities.user_jwt_entity import UserJwt
from ew_dsb_client_lib.auth.entities.claim_data_entity import ClaimData
from ew_dsb_client_lib.auth.entities.public_claim_entity import PublicClaim

from identity import create_token

@dataclass()
class ReadPayload(DataClassJsonMixin):
    # EnergyWeb DID
    asset_did: str
    # Lectura meter
    meter_power: float
    # Lectura generación PV
    pv1_power: float
    # Lectura meter Line 1
    sl1_power:float
    # Read timestamp
    timestamp: int

READ_SCHEMA: dict = {
    "type": "object",
    "anyOf": [
        { "required": ["asset_did"] },
        { "required": ["meter_power"] },
        { "required": ["pv1_power"] },
        { "required": ["sl1_power"] },
        { "required": ["timestamp"] },
    ],
    "properties": {
        "asset_did": {
            "type": "string"
        },
        "meter_power": {
            "type": "number"
        },
        "pv1_power": {
            "type": "number"
        },
        "sl1_power": {
            "type": "number"
        },
        "timestamp": {
            "type": "integer"
        },
    },
    "additionalProperties": False
}
MESSAGE_SCHEMA: dict = {
    "type": "object",
    "anyOf": [
        { "required": ["fqcn"] },
        { "required": ["payload"] },
        { "required": ["signature"] }
    ],
    "properties": {
        "fqcn": {
            "type": "string"
        },
        "payload": {
            "type": "string"
        },
        "signature": {
            "type": "string"
        },
  },
  "additionalProperties": False
}

dotenv_path = os.path.join(os.path.abspath('./'), '.env')
dsbClient:DSBClient = DSBClient()

def create_identity( asset_DID:str) -> str:
    print('Create an Identity Token')
    try:
        claim_data:ClaimData = ClaimData(
            blockNumber=999999999999
        )
        claim:PublicClaim = PublicClaim(
            claimData=claim_data,
            iss=asset_DID
        )
        payload:str = claim.to_json()
        
        jwt_identity_token:str = create_token(payload)
        # logger.debug(vars(userJwt))
        return jwt_identity_token
    except Exception as error:
        print(error)

def create_mock_payload(asset_DID) -> ReadPayload:
    asset_did:str = asset_DID
    meter_power:float = float("{0:.2f}".format(random.uniform(2700.5, 3500.5))) 
    pv1_power:float = float("{0:.2f}".format(random.uniform(2700.5, 3500.5))) 
    sl1_power:float = float("{0:.2f}".format(random.uniform(2700.5, 3500.5)))
    timestamp:int = pendulum.now().int_timestamp

    mock_payload:ReadPayload = ReadPayload(
        asset_did,
        meter_power,
        pv1_power,
        sl1_power,
        timestamp
    )
    return mock_payload


async def publish_to_channel(fqcn:str, payload:ReadPayload):    
    try:
        # Validate payload
        validate(instance=payload.to_dict(), schema=READ_SCHEMA)
        json_payload = payload.to_json()
        # Sign message
        signature:str = create_token(json_payload)
        # Create message  
        publish_message_dto = PublishMessageDto(
            fqcn,
            json_payload,
            signature
        )
        print(publish_message_dto)
        # Validate message
        validate(instance=publish_message_dto.to_dict(), schema=MESSAGE_SCHEMA)
        # Publish message
        published:bool = await dsbClient.message.publish(publish_message_dto)

    except Exception as error:
        print(error)

async def publisher_worker(simulator_read_q:queue.Queue):
    # Simulator reading interval in seconds
    interval:int = 5 #int(os.getenv('PUBLISH_INTERVAL'))
    # Electracaldense channel
    fqcn:str = os.getenv("FQCN")

    while True:
        await asyncio.sleep(delay=interval)
        # Read from simulator queue
        payload = simulator_read_q.get()
        # Updating timestamp
        payload.timestamp = pendulum.now().int_timestamp
        await publish_to_channel(fqcn, payload)
        # Indicate completion
        simulator_read_q.task_done()

async def simulator_worker(simulator_read_q:queue.Queue):
    asset_DID = os.getenv("ASSET_DID")
    # Create a mock Payload instance
    mock_payload:ReadPayload = create_mock_payload(asset_DID)
    while True:
        simulator_read_q.put(mock_payload)


async def sign_in_user(identity_token:str) -> UserJwt:
    print('Sign In User')
    try:
        userJwt:UserJwt = await dsbClient.auth.sign_in(identity_token)
        print(userJwt)
        # logger.debug(vars(userJwt))
        return userJwt
    except Exception as error:
        print(error)

async def init_credentials():
    user_DID:str = os.getenv("ASSET_DID")
    # Sign In User
    identity_token:str = create_identity(user_DID)
    user_jwt:UserJwt = await sign_in_user(identity_token)
    # print(user_jwt)
    dsbClient.update(bearer_token=user_jwt.token)

async def main():
    # Init credentials
    await init_credentials()
    # Init simulator Read queue
    simulator_read_q = queue.Queue()
    # # Init publisher worker
    publish_t = threading.Thread(target=asyncio.run, args=(publisher_worker(simulator_read_q),), daemon=True)
    publish_t.start()
    # # Init simulator worker
    simulator_t = threading.Thread(target=asyncio.run, args=(simulator_worker(simulator_read_q),), daemon=True)
    simulator_t.start()
    # # Blocks the calling thread until terminates
    publish_t.join()
    simulator_t.join()

asyncio.run(main())