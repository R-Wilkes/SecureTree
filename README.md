# SecureTree Info

- SecureTree is meant to be useful in the IRSec competitions
- It provides a bunch of simple tools/features that make securing windows automated and or easier

# IRSec
- Its a blue teaming competitions, slightly to Cyberpatriot
- Difference being Red team has full control of all machines and will be breaking every single one
- SecureTree can only really delay the effects of red team
- Also have to wright injects and reports on what happens


# Running the Start.ps1

### Starting
Run as administrator Powershell terminal <br>
```
.\Start.ps1
```

### Execution Policy

By default windows does not allow unauthorized scripts to run, to change this run this command in the powershell terminal <br>
Run this command before trying to run the Start.ps1 <br>
```
Set-ExecutionPolicy bypass
```

# TIPS

fast_mode will allow the script to go faster, can also set the time of sleep statements <br>

debug_mode will make screen not clear, All errors become Inquire <br>

Default error handling is set to Stop <br>

If Manually Editing Users and changing names, don't use any number or special characters <br>


# Config

## Overview

There is a config file located in the Config folder that will let you set certain things for the auto script to do<br>
Mainly there so you can get a little bit more efficiency out of this script<br>
The readme for the config is in the config folder<br>

## Config Information

Information on what the settings do in the config can be found [Here](Config/Readme.md "Config Settings")

# Passwords

Passwords are defined in this script, but will most likely change when in comp <br>

NOTE: Your not gonna find the passwords in this script, the passwords can be found [Here](https://www.youtube.com/watch?v=dQw4w9WgXcQ)  <br>

# Users

User files are located in ./UserLists <br>
Fill out the files before starting the script <br>
Used to accurately report/make changes when dealing with users on the machine <br>

## Local Users
These are users that only get set if the machine is NOT part of AD <br>

- Set local users in the Local_Users.txt
- Set local admins in the Local_Admins.txt

## Domain Users
These are users that only get set if the machine IS apart of AD <br>

- Set domain users in the Domain_Users.txt
- Set domain admins in the Domain_Admins.txt

## Manual Mode

Can also set users from the manual mode menu <br>
Will show two different menus depending if on AD <br>
Lets you do simple configuration stuff from the terminal <br>
Can also just do it using the default user GUI on windows <br>


# Software

The files located in the software are listed below <br>

Not allowed to enable/install any sort of Anti-Virus <br>

-Firefox Installer <br>
-Chrome Installer <br>
-Sysinternals <br>
-RevoUninstaller Installer <br>

# WARNINGS

The creator of this glorious script is not responsible for the destruction of your IRSec machine or ANY machine this script runs on <br>

ONLY meant for use by authorized users and on machines in the IRSec competitions <br>

RUN THIS SCRIPT AT YOUR OWN DISCRETION! <br>