# !/bin/bash

# Software Update
# Automatically keep my Mac up to date
printf "Enable Automatically keep my Mac up to date.\\n"
softwareupdae --schedule on > /dev/null 2>&1

# Check for updates


# Download nesupdates when available


# Install macOS updattes
printf "Installing needed updates.\\n"
softwareupdate -i -a > /devnull 2>&1


# Install app updates from the App Store


# Install system data files and security updates


# Sharing
# Fire Sharing


# Remote Login
printf "Disable Remote Login"
systemsetup if -setremotelogin off > /dev/null 2>&1



# Remote Management


# Remote Apple Events


# Internet Sharing


# Set data and time automatically


# Desktop & Screen Saver
# Show screen saver after (20 Minutes)


# Security & Privacy
# General

# Require password (5 minutes) after sleep or screen saver begins
# Disable automtic login
# Allow apps downloaded from: 
# App Store and identified developers



# Firewall: On
printf "Enabling Firewall.\\n"
defaults write /Library/Preferences/com.apple.alf globalstate 1 > /dev/null 2>&1

# Check antivirus software


# Finishing up.
timed="$((SECONDS / 3600)) Hours $(((SECONDS / 60) % 60)) Minutes $((SECONDS % 60)) seconds"
printf "It took %s to enable macOS baseline security settings.\\n" "$timed"