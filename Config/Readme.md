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

### find_files (True, False)
- Allows the Auto1 Script to search the most important directory's for banned files, and will report them to you <br>

### run_winPEAS (True, False)
- Will run the winPEAS script, meant for red-team, but should give some ideas of places need patching <br>
- NOTE: Antivirus may flag it, thats why its in a zip <br>

## Auto Fix

### set_local_users (True, False, Ask)
- Sets local users based on the users defined in the local_admins/users files <br>
- WARNING: Won't mess with your current user, but can very easily mess up the scoring system user <br>

### enable_firewall (True, False, Ask)
- Enables the firewall with a bunch of rules set <br>
- Most deadly, could block a needed port <br>

### run_service_config (True, False, Ask)
- Will set a lot of services either on or off <br>
- WARNING: Disables RDP so could brick you if thats what your using to access

### set_registry_keys (True, False, Ask)
- Sets a bunch of keys a took from somewhere, so could be very bad <br>

### run_Policys (True, False, Ask)
- Sets a lot of policys that are generally for security <br>
- Will only run if Auto Fix is true <br>
- WARNING: This will break your computer somewhere, go for it anyway <br>

### run_auto_fix.bat (True, False, Ask)
- Sets a bunch of stuff, reg keys, disables guest account, stuff like that <br>
- Will only run if Auto Fix is true <br>
- WARNING: This will break your computer everywhere <br>

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
