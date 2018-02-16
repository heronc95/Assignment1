#!/usr/bin/env python3

import tweepy
import socket
import requests
import time
import sys
import re, string
import hashlib
import argparse
import pickle
from clientKeys import authentication
from cryptography.fernet import Fernet
from subprocess import call

cmd_beg='espeak '
cmd_end=' 2>/dev/null'

# The constants for the location of the various components in the message tuple
QUESTION_NUM = 0
HASH_NUM = 1

#Global variable to help with the functions
args = None
def speak_string(speakme):
    
    speakme = speakme.replace(' ', '_')
    print("[Checkpoint] Speaking: " + speakme)
    call([cmd_beg+speakme+cmd_end], shell=True)

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
        print("[Checkpoint] Checksum is VALID")
        # Now we can decrypt the message that was sent
        # First get the key all set
        decrypter = Fernet(decrypt_key)
        # Now decrypt the message
        answer = bytes(decrypter.decrypt(data_tuple[QUESTION_NUM]))
        print("[Checkpoint] Decrypt: Using Key: " + str(decrypt_key) + " | Plaintext: " + answer)

        return str(bytes.decode(answer))
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
    print("[Checkpoint] Encrypt: Generated Key: " + str(key) + " | Ciphertext: " + str(encrypted_question))

    # Get the md5 hash of the question
    hasher.update(encrypted_question)
    hash = hasher.digest()
    print("[Checkpoint] Generated MD5 Checksum:: " + hash)

    tuple_to_return = (key, encrypted_question, hash)
    return tuple_to_return




class TwitterListener(tweepy.StreamListener):
    def on_status(self, status):

        # This is where it parses the tweet
        get_tweet(status)
    
    def on_error(self, status_code):
        if status_code == 403:
            print("The request was refused access")
            return False

def get_tweet(tweet):
    # This holds the last key sent in a list of length one
    fernet_last_sent = [None]

    # Pulls the string out of the tweet
    raw_tweet = strip_all_entities(tweet.text).encode('UTF-8').decode('UTF-8')
    print("[Checkpoint] New Tweet: " + raw_tweet + " | User: " + str(tweet.user.id))

    # Begin tweet handling here
    tup = create_message_packet(raw_tweet, fernet_last_sent)

    # Dump the message into pickle
    transmit_me = pickle.dumps(tup)
    print("[Checkpoint] Sending data: " + transmit_me)
    # Send data
    sock.sendall(transmit_me)

    # Recieve from the socket
    data = sock.recv(args.SOCKET_SIZE)
    print("[Checkpoint] Received data: " + data)

    answer = parse_question_message(data, fernet_last_sent[0])

    #this puts the answer in the correct format to be spoken
    string_answer = strip_all_entities(answer).encode('UTF-8').decode('UTF-8')
    speak_string(string_answer)

#this function will parse the text for only the question
def strip_all_entities(text):
    #any of these characters will be removed in the parsed tweet
    entity_prefixes = ['@', '#', '_']
    for separator in string.punctuation:
        if separator not in entity_prefixes:
            text = text.replace(separator, ' ')
    words = []
    for word in text.split():
        word = word.strip()
        if word:
            if word[0] not in entity_prefixes:
                words.append(word)
    return ' '.join(words)

if __name__ == '__main__':
    # Setting up the argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--SERVER_IP", type=string)
    parser.add_argument("-p", "--SERVER_PORT", type=int)
    parser.add_argument("-z", "--SOCKET_SIZE", type=int)
    parser.add_argument("-t", "--HASHTAG", type=string)

    # This gets the arguments from the user, access them through SERVER_PORT, etc
    args = parser.parse_args()


    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.SERVER_IP, args.SERVER_PORT)
    print('[Checkpoint] Connecting to {} on port {}'.format(*server_address))
    sock.connect(server_address)


    # use variable auth for the class in clientKeys
    auth = authentication()

    #pull the keys from the clientKeys file
    consumer_key = auth.getconsumer_key()
    consumer_secret = auth.getconsumer_secret()
    access_token = auth.getaccess_token()
    access_token_secret = auth.getaccess_token_secret()

    # use the consumer keys
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.secure = True
    # use the access tokens
    auth.set_access_token(access_token, access_token_secret)

    api = tweepy.API(auth, wait_on_rate_limit=True, wait_on_rate_limit_notify=True, retry_count=10, retry_delay=5,
                     retry_errors=5)

    streamListener = TwitterListener()
    myStream = tweepy.Stream(auth=api.auth, listener=streamListener)
    # look for any tweets with the hashtag #ECE4564_T11
    myStream.filter(track=[args.HASHTAG], async=True)

    print("[Checkpoint] Listening for Tweets that contain: " + args.HASHTAG)
    


