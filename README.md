# DENC
DENC - Free, Fast, Simple and Mass file encryption and decryption Tool using AES 256 CBC encryption
under MIT License

# LatestVerison
<b>V 1.3</b> <br>
Bug Fixed : Target file/files suppose to have been existed before process.<br>
New Feature : Colorizes the output for better reads.<br>
New Feature : Add a new CLI input arguments structure.
<br>

# PreviousVerisons
<b>V 1.2</b> <br>
Bug Fixed : Target file suppose to have a valid length not the zero , then its allowed to remove the source file.<br>
New Feature : Set a mechanism to keep the file modification time unchanged after the Encrypt/Decrypt.<br>
New Feature : Performing better interact cli.
<hr>

# Usage :
	>>php denc.php --method dec|enc --pass <password> --files <files_selection_regex_pattern>

# Example : 
	>>php denc.php -m enc -p testpass -f ./htdoc/*.html
	>>php denc.php -m dec -p otherpass -f /home/txts/*.txt
	>>php denc.php --method enc --pass anotherpass --files /web/backup_*.zip

# NOTE : 
	+ NEVER DONT TRY TO DELETE `.dont-remove.conf` FILES IN WORKING DIRCTORIES.
	+ WE DONT ACCEPT ANY RESPONSIBILITY OF ANY KIND OF DATA FILES LOST WHILE USING THIS SCRYPT.
# Coded BY :
	GitHub.com/ @SaeedEY
