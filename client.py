import socket
import os
from twython import TwythonStreamer
from clientKeys import (
    TWITTER_CONSUMER_KEY,
    TWITTER_CONSUMER_SECRET,
    TWITTER_ACCESS_TOKEN,
    TWITTER_ACCESS_TOKEN_SECRET
)
def say(something):
    os.system('espeak -ven+f2 "{0}"'.format(something))

class MyStreamer(TwythonStreamer):
    def on_success(self, data):
        if 'text' in data:
            print(data['text'])
            say(data['text'])
stream = MyStreamer(
    TWITTER_CONSUMER_KEY,
    TWITTER_CONSUMER_SECRET,
    TWITTER_ACCESS_TOKEN,
    TWITTER_ACCESS_TOKEN_SECRET
)
stream.statuses.filter(track="#ECE4564_T11")



