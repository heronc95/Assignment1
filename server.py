import wolframalpha
import argparse
import socket
import hashlib
import pickle
import serverKeys
from cryptography.fernet import Fernet

# Descriptive defines to use in the code
RESULT_NUM_WOLFRAM = 1
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
        question_bytes = bytes(decrypter.decrypt(data_tuple[QUESTION_NUM]))
        #Now return the string that was sent
        return str(bytes.decode(question_bytes))
    else:
        # Then the hash was not good and should not let it decode
        return None

def get_answer_wolfram(user_query):
        '''
        This is used to query wolfram alpha. It returns a string if wolfram actually answered the question
        and None if it didn't find anything
        :param user_query:
        :return:
        '''
        client = wolframalpha.Client(serverKeys.appId)

        # This is where I ask the user to send me the question
        res = client.query(user_query)
        if res['@success']:
            try:
                # Result pod is a dictionary that holds the result, have to get that from a list
                result_pod = list(res.pods)
                result_pod = dict(result_pod[RESULT_NUM_WOLFRAM])

                # Now get the plaintext response from the subpod from that with the result, so many dicts
                text_result = result_pod['subpod']['plaintext']
                return text_result
            except KeyError:
                print("There was an error in looking up the keys in the subpods");
        else:
            # Wolfram couldn't find an answer
            print("Wolfram Alpha said it couldn't find the answer")
        return None



# Start execution here --------------------------------------------------------------------


#Setting up the argument parser
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--SERVER_PORT", help="This is the port the server is listening on, greater that 1024", type=int)
parser.add_argument("-b", "--BACKLOG_SIZE", help="This is the backlog size of the socket I believe", type=int)
parser.add_argument("-z", "--SOCKET_SIZE", help="This is the backlog size of the socket I believe", type=int)

#This gets the arguments from the user, access them through SERVER_PORT, etc
args = parser.parse_args()

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)

        #Wait fo receive data on the socket
        data = connection.recv(1024)
        print('received {!r}'.format(data))
        # parse the data from the client
        question = parse_question_message(data)
        print("The question was: " + question)

        #Get the answer from wolfram alpha
        answer = str(get_answer_wolfram(question))

        print("The answer is : " + answer)

        if data:
            print('sending data back to the client')
            connection.sendall(data)


    finally:
        # Clean up the connection
        connection.close()



#Start the execution here


