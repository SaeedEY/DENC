# DENC
DENC - Free, Fast, Simple and Mass file encryption and decryption Tool using AES 256 CBC encryption
under MIT License

#LatestVerison
V 1.2
Bug Fixed : Target file suppose to have a valid length not the zero , then its allowed to remove the source file.
New Feature : Set a mechanism to keep the file modification time unchanged after the Encrypt/Decrypt.
New Feature : Performing better interact cli.

<hr>

# Usage :
	>>php denc.php <dec/enc> <password> <files_selection_regex_pattern>

# Example : 
	>>php denc.php enc testpass ./htdoc/*.html
	>>php denc.php dec otherpass home/txts/*.txt
	>>php denc.php enc anotherpass /web/backup.zip

# NOTE : 
	+ NEVER DONT TRY TO DELETE `.dont-remove.conf` FILES IN WORKING DIRCTORIES.
	+ WE DONT ACCEPT ANY RESPONSIBILITY OF ANY KIND OF FILE LOSING WHILE USING THIS SCRYPT.
# BY :
	GitHub.com/ @SaeedEY
