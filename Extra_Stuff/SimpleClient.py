#socket_echo_client.py
import socket
import sys
import hashlib
import pickle
from cryptography.fernet import Fernet

# The constants for the location of the various components in the message tuple
QUESTION_NUM = 0
HASH_NUM = 1




def parse_question_message(raw_data, decrypt_key):
    '''
    This is the handler for reading messages from the sender. It deserializes the data,
    then loads it into a tuple object for further analyises.
    :param raw_data:
    :param decrypt_key: The key that was last sent to decode the return message
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
        decrypter = Fernet(decrypt_key)
        # Now decrypt the message
        question = bytes(decrypter.decrypt(data_tuple[QUESTION_NUM]))
        return str(bytes.decode(question))
    else:
        # Then the hash was not good and should not let it decode
        return None

def create_message_packet(string_message, fernet_key_last_sent):
    '''
    This function will build the tuple of the given message and return it. Based of the spec
    the tuple has (Key, Encypted Message, Checksum of message)
    :param string_message:
    :return: A tuple of the objects to transmit
    '''

    key = Fernet.generate_key()
    fernet_key_last_sent[0] = key
    f = Fernet(key)
    hasher = hashlib.md5()
    encrypted_question = f.encrypt(string_message.encode())

    # Get the md5 hash of the question
    hasher.update(encrypted_question)
    hash = hasher.digest()

    tuple_to_return = (key, encrypted_question, hash)
    return tuple_to_return


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# This holds the last key sent in a list of length one
fernet_last_sent = [None]

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)


#Make the encyption stuff here
tup = create_message_packet("How big is jupiter?", fernet_last_sent)

#Dump the message into pickle
transmit_me = pickle.dumps(tup)


try:

    # Send data
    sock.sendall(transmit_me)

    data = sock.recv(500)

    answer = parse_question_message(data, fernet_last_sent[0])
    print("I got this: " + answer)
finally:
    print('closing socket')
    sock.close()