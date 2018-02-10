#socket_echo_client.py
import socket
import sys
import hashlib
import pickle
from cryptography.fernet import Fernet

# The constants for the location of the various components in the message tuple
KEY_NUM = 0
QUESTION_NUM = 1
HASH_NUM = 2


def parse_question_message(raw_data):
    '''
    This is the handler for reading messages from the sender. It deserializes the data,
    then loads it into a tuple object for further analyises.
    :param raw_data:
    :return: A valid question string if correct message is received, or None if nothing was there
    '''
    # first have to load the data from the serialized string back into a tuple
    data_tuple = tuple(pickle.loads(raw_data))

    # Check the hash first, by rehashing it
    hash_checker = hashlib.md5()
    hash_checker.update(data_tuple[QUESTION_NUM])
    received_hash = hash_checker.digest()
    if received_hash == data_tuple[HASH_NUM]:
        # Now we can decrypt the message that was sent
        # First get the key all set
        decrypter = Fernet(data_tuple[KEY_NUM])
        # Now decrypt the message
        question = str(decrypter.decrypt(data_tuple[QUESTION_NUM]))
        print("\n\n\n\n The question I got was this! " + question)
        return question
    else:
        # Then the hash was not good and should not let it decode
        return None

def create_message_packet(string_message):
    '''
    This function will build the tuple of the given message and return it. Based of the spec
    the tuple has (Key, Encypted Message, Checksum of message)
    :param string_message:
    :return: A tuple of the objects to transmit
    '''

    key = Fernet.generate_key()
    f = Fernet(key)
    hasher = hashlib.md5()
    encrypted_question = f.encrypt(string_message.encode())

    # Get the md5 hash of the question
    hasher.update(encrypted_question)
    hash = hasher.digest()

    tuple_to_return = (key, encrypted_question, hash)

    # Now we have the three packets to hash
    print(hash)
    print(encrypted_question)

    print(f.decrypt(encrypted_question))

    f.decrypt(encrypted_question)

    return tuple_to_return




# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)


#Make the encyption stuff here
tup = create_message_packet("Where in the world is Andrew Spencer")

print("The returned tuple is:" + str(tup))
print("Pickling the shit out of it: ")

#Dump the message into pickle
transmit_me = pickle.dumps(tup)


try:

    # Send data
    sock.sendall(transmit_me)

    # Look for the response
    amount_received = 0
    amount_expected = len(transmit_me)

    data = sock.recv(500)
    amount_received += len(data)
    print('received {!r}'.format(data))
    parse_question_message(data)

finally:
    print('closing socket')
    sock.close()