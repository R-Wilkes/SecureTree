# INFO
- This is a simple guide to help you understand what certain setting do in the config <br>

## Possible Values
- True = Yes <br>
- False = No <br>
- Ask = Script will ask your input Y/N <br>
- Number = Int or Float Ex. Int/Float, Float or Int <br>
- Entering an incorrect config setting will cause the script to crash <br>
- 'Ask' can be used for all the settings if you want, but its only useful on the setting specified <br>
- Any Value that has a '*' next to it is changeable while the script is running (Can do it realistically for all values, not recommended)<br>

## Quality of Life settings

### new_CLI (True, False)
- Uses a new version of the CLI, looks better and better navigation <br>

### fast_mode (True, False)
- Changes the script into fast mode, sets all the sleep statements to time specified <br>

### fast_mode_time (Number:Int/Float)
- Sets the time of the fast mode <br>

### debug_mode (True, False) *
- Good for debugging, removes most of the clear-screen statements in the script <br>
- Screen does not get cleared when something is printed out <br>

## Auto Scripts

### run_AutoDiagnostic (True, False)
- Allows Auto to run the AutoDiagnostics script <br>

### run_AutoFix (True, False, Ask)
- Allows Auto to run AutoFix script <br>
- WARNING: Can brick computer for the comp <br>

## Auto Diagnostics

Automatically checks domain and local users on the AD/DC <br>
Along with Guest user and SMBv1, starts monitors <br>
Also Prints out any installed programs <br>

Keep in mind that on DC there are only domain users, local users do not exist for DC <br>
Any machine under the domain is can have domain users and local users <br>

Optional settings are down below


### find_files (True, False)
- Allows the Auto1 Script to search the most important directory's for banned files, and will report them to you <br>

### run_winPEAS (True, False)
- Will run the winPEAS script, meant for red-team, but should give some ideas of places need patching <br>
- NOTE: Antivirus may flag it, thats why its in a zip <br>

### remote_users (True, False Ask)
- Will go through any machines connect to the domain and manage their local users <br>
- Makes it easy to manage all local users on a domain rather than putting this script on each machine <br>
- Takes a good amount of time tho <br>

## Auto Fix

Similar replica to AutoDiagnostics <br>
Difference is this makes changes to your systems foretold by the AutoDiagnostics script <br>
Can horrificly mess up your machine if you enable things that should not be enabled with this config <br>

### set_local_users (True, False, Ask)
- Sets local users based on the users defined in the local_admins/users files <br>
- WARNING: Won't mess with your current user, but can very easily mess up the scoring system user <br>

### set_domain_users (True, False, Ask)
- Sets domain users based on the users defined in the domain admins/users files <br>
- WARNING: Won't mess with your current user, but can very easily mess up the scoring system user <br>

### set_remote_users (True, False, Ask)
- Sets local users on other machines based on the Local users/admins files <br>
- WARNING: Can be horrific if stopped mid way, cause ya know, its editing other users on other MACHINES <br>

### enable_firewall (True, False, Ask)
- Enables the firewall with a bunch of rules set <br>
- Most deadly, could block a needed port <br>

### run_service_config (True, False, Ask)
- Will set a lot of services either on or off <br>
- WARNING: Disables RDP so could brick you if thats what your using to access

### password_shuffle (True, False, Ask)
- Automatically sets remote local users passwords constantly <br>
- Hopefully delays red team <br>

## Password Policy's

- Note that these only get set if Auto Fix is set to True

### set_password_policy (True, False)
- Sets the password policy to the values defined in the config (below) <br>

### min_password_length (Number:Int)
- Minimum password length requirement <br>

### min_password_age (Number:Int)
- Minimum password age, the amount of days you have to wait before changing passwords <br>

### max_password_age (Number:Int)
- Maximum password age, the maximum amount of days before you have to change your password<br>

### unique_password (Number:Int)
- How many passwords can be reused, ex this password can only be used for a (Number:Int) of accounts <br>

### lock_out_threshold (Number:Int)
- How many invalid password attempt before lockout <br>

### lock_out_duration (Number:Int)
- How long after threshold is reached before another password attempt <br>
