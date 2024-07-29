#!/bin/bash

# Copy the Python extcap interface to the Wireshark extcap directory
cp trailshark-capture.py ~/.local/lib/wireshark/extcap/

# Copy the entire 'lib' directory, preserving attributes, to the Wireshark extcap lib directory
cp -rf lib/* ~/.local/lib/wireshark/extcap/lib/

# Set read, write, and execute permissions recursively for the extcap lib directory
chmod -R +x ~/.local/lib/wireshark/extcap/lib

# Make the trailshark-capture.py script executable
chmod +x ~/.local/lib/wireshark/extcap/trailshark-capture.py

# Copy all Lua scripts to the Wireshark plugins directory
cp trailshark-plugin/*.lua ~/.local/lib/wireshark/plugins/

# Create the Wireshark profiles directory if it does not exist
mkdir -p ~/.config/wireshark/profiles

# Copy the trailshark-profile directory to the Wireshark profiles directory
cp -r trailshark-profile ~/.config/wireshark/profiles/
