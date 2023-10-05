#!/bin/bash

length="$1"
if [ -z "$length" ]; then
    length=12  # Default password length
fi

# Define the character set for the password
characters="A-Za-z0-9"

# Use /dev/urandom to generate random bytes and tr to shuffle them
LC_ALL=C tr -dc "$characters" < /dev/urandom | head -c "$length"