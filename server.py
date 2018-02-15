#!/usr/bin/env python3
import wolframalpha
import argparse
import socket
import hashlib
import pickle
import serverKeys
from subprocess import call

from cryptography.fernet import Fernet

# Descriptive defines to use in the code
RESULT_NUM_WOLFRAM = 1
# The constants for the location of the various components in the message tuple
KEY_NUM = 0
QUESTION_NUM = 1
HASH_NUM = 2

# These are the commands for speaking a string
cmd_beg= 'espeak '
cmd_end= ' 2>/dev/null' # To dump the std errors to /dev/null


# The library, and method of calling the speak is from https://www.dexterindustries.com/howto/make-your-raspberry-pi-speak/
def speak_string(speak_me):
	"""
	This what speaks the text that was spoken
	"""
	# Print what I am doing here
	print("[Checkpoint] Speaking: " + speak_me)

	#Rename the stuff hrere
	speak_me = speak_me.replace(' ', '_')
	# Speak the word and then print
	call([cmd_beg+speak_me+cmd_end], shell=True)


def parse_question_message(raw_data, fernet_key_local):
    '''
    This is the handler for reading messages from the sender. It deserializes the data,
    then loads it into a tuple object for further analyises.
    :param raw_data:
    :param fernet_key_local: The key to update
    :return: A valid question string if correct message is received, or None if nothing was there
    '''

    # first have to load the data from the serialized string back into a tuple
    data_tuple = tuple(pickle.loads(raw_data))
    #Update the key
    fernet_key_local[0] = data_tuple[KEY_NUM]

    # Check the hash first, by rehashing it
    hash_checker = hashlib.md5()
    hash_checker.update(data_tuple[QUESTION_NUM])
    received_hash = hash_checker.digest()
    if received_hash == data_tuple[HASH_NUM]:
        print('[Checkpoint] Checksum is VALID')
        # Now we can decrypt the message that was sent
        # First get the key all set
        decrypter = Fernet(fernet_key_local[0])
        # Now decrypt the message
        question_bytes = bytes(decrypter.decrypt(data_tuple[QUESTION_NUM]))
        print('[Checkpoint] Decrypt: Using Key: ' + str(fernet_key_local[0]) + ' | Plaintext: ' + str(question_bytes))

        #Now return the string that was sent
        return str(bytes.decode(question_bytes))
    else:
        # Then the hash was not good and should not let it decode
        return None


def create_message_packet(string_message, key):
    """
    This function will build the tuple of the given message and return it. Based of the spec
    the tuple has (Encypted Message, Checksum of message), dont need the key because it is
    the client's
    :param string_message: The string answer that you want to transmit back to the clients
    :param key: The key that was sent earlier, and is used to encrypt the message back
    :return: A tuple of the objects to transmit
    """

    f = Fernet(key)
    hasher = hashlib.md5()
    encrypted_question = f.encrypt(string_message.encode())
    print('[Checkpoint] Encrypt: Generated Key: ' + str(key) + ' | Ciphertext: ' + str(encrypted_question))
    # Get the md5 hash of the question
    hasher.update(encrypted_question)
    hash = hasher.digest()
    print('[Checkpoint] Generated MD5 Checksum: ' + str(hash))
    # This is the tuple of all the packets, and just need to pickle it
    tuple_to_return = (encrypted_question, hash)

    return tuple_to_return


def get_answer_wolfram(user_query):
        '''
        This is used to query wolfram alpha. It returns a string if wolfram actually answered the question
        and None if it didn't find anything
        :param user_query:
        :return:
        '''

        appId = serverKeys.wolfram_alpha_appid
        client = wolframalpha.Client(appId)
        error_msg = "Wolfram Alpha said it couldn't find the answer"
        try:
            # This is where I ask the user to send me the question
            print('[Checkpoint] Sending question to Wolframalpha: ' + user_query)
            res = client.query(user_query)
            if res['@success'] == 'true':
                try:
                    # Result pod is a dictionary that holds the result, have to get that from a list
                    result_pod = list(res.pods)
                    result_pod = dict(result_pod[RESULT_NUM_WOLFRAM])

                    # Now get the plaintext response from the subpod from that with the result, so many dicts
                    text_result = result_pod['subpod']['plaintext']
                    print('[Checkpoint] Received answer from Wolframalpha: ' + text_result)
                    return text_result

                except KeyError:
                    print("There was an error in looking up the keys in the subpods");
        except:
            print(error_msg + " <- returning that.")

        return error_msg



# Start execution here --------------------------------------------------------------------

# Local variables to use
fernet_key = [None]

# Setting up the argument parser
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--SERVER_PORT", help="This is the port the server is listening on, greater that 1024", type=int)
parser.add_argument("-b", "--BACKLOG_SIZE", help="This is the backlog size of the socket I believe", type=int)
parser.add_argument("-z", "--SOCKET_SIZE", help="This is the backlog size of the socket I believe", type=int)

# This gets the arguments from the user, access them through SERVER_PORT, etc
args = parser.parse_args()

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Listens on all addresses for networks
address = "0.0.0.0" 

# Bind the socket to the port
server_address = (address, args.SERVER_PORT)
print('[Checkpoint] Created socket at {} on port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections, with the specified number of connections
sock.listen(args.BACKLOG_SIZE)


# Wait for a connection
print('[Checkpoint] Listening for client connections')
connection, client_address = sock.accept()
print('[Checkpoint] Accepted client connection from {} on port {}'.format(*client_address))

try:
    while True:
        #Wait fo receive data on the socket
        data = connection.recv(args.SOCKET_SIZE)
        print('[Checkpoint] Recieved data:' + str(data))
        # parse the data from the client
        question = parse_question_message(data, fernet_key)
        # Speak the string real quick
        speak_string(question)
        #Get the answer from wolfram alpha
        answer = get_answer_wolfram(question)
        if answer != None:
            # Make the answer payload back to the client here
            response_tuple = tuple(create_message_packet(answer, fernet_key[0]))
            # Serialize and send to the client
            send_data = pickle.dumps(response_tuple)
            print('[Checkpoint] Sending data: ' + str(send_data))
            connection.sendall(send_data)

finally:
    # Clean up the connection
    connection.close()


