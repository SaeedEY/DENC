<?php
$intro = '
****************************************************************** 
 * ＤＤＤＤＤ      ＥＥＥＥＥＥ      ＮＮＮ     ＮＮ        CCCCCCC  *
 * ＤＤ ＤＤＤ     ＥＥ             ＮＮＮＮ   ＮＮ       CCCC       *
 * ＤＤ    ＤＤ    ＥＥＥＥＥ       ＮＮ ＮＮ  ＮＮ      CCC          *
 * ＤＤ    ＤＤ    ＥＥＥＥＥ       ＮＮ  ＮＮ ＮＮ      CCC          *
 * ＤＤ ＤＤＤ     ＥＥ             ＮＮ   ＮＮＮＮ      CCCC        *
 * ＤＤＤＤＤ      ＥＥＥＥＥＥ      ＮＮ     ＮＮＮ        CCCCCCC  *
 ****************************************************************** 
 *	Free, Fast, Simple and Mass file encryption and decryption Tool
 *	 	using AES 256 CBC encryption.
 *
 *	Usage: 	  >php denc.php --method dec|enc --pass <password> --files <regex_pattern>
 *
 *	Example:  >php denc.php -m enc -p testpass -f ./htdoc/*.html
 *			  >php denc.php -m dec -p otherpass -f home/txts/*.txt
 *			  >php denc.php -=method enc --pass anotherpass --files /web/backup.zip
 *	
 *	!! NOTE : + NEVER DONT TRY TO DELETE `.dont-remove.conf` FILES IN
 * 		   		WORKING DIRCTORIES.
 *		   	  + WE DONT ACCEPT ANY RESPONSIBILITY OF ANY KIND OF DATA
 *		   		FILES LOST WHILE USING THIS SCRYPT.
 * 	Coded BY : GitHub.com/SaeedEY
 *
 * 	[latest]
 *	Version 1.3
 *		+ colorizes the output log
 *		+ change the input arguments structure
 *		+ fix a non-existed files bug
 *******************************************************************
 *	Version 1.2
 *		+ target file suppose to have a valid length 
 *			not the zero , then its allowed to remove the source file
 *		+ set a mechanism to keep the file modification time 
 *			unchanged after the Encrypt/Decrypt
 *		+ performing better intract cli with the user
 *******************************************************************
 *	Version 1.1 
 *		+ a full of bug script which i suppose to fix them in the
 *			next updates :)
 *******************************************************************
 * 	MIT License
 *
 *	Copyright (c) 2021 SaeedEY
 *
 *	Permission is hereby granted, free of charge, to any person obtaining a copy
 *	of this software and associated documentation files (the "Software"), to deal
 *	in the Software without restriction, including without limitation the rights
 *	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *	copies of the Software, and to permit persons to whom the Software is
 *	furnished to do so, subject to the following conditions:
 *
 *	The above copyright notice and this permission notice shall be included in all
 *	copies or substantial portions of the Software.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *	SOFTWARE.
 *
 *********************************************************************';

/**
 * PreDefined Variables
 */
ini_set('memory_limit','8192M');
define("PREFIX","__");
define("METHOD","AES-256-CBC");
define("IV",chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0));
define("CHECKFILE", '.dont-remove.conf');

/**
 *	Return seprated file name and parent directory
 */
function fileProperties(string &$file_path) : array{
	$dir_path = dirname($file_path);
	$file_name = substr($file_path,strrpos($file_path,"\\"));
	if($file_name[0] == '\\') $file_name = substr($file_name, 1);
	return [$dir_path,$file_name];
}

/**
 *	Return a generated Key as user given password
 */
function generateKey(string & $password){
	return substr(hash('sha256', $password, true), 0, 32);
}

/**
 *	Append the given directory cryption history
 */
function setDirectoryCryptionHistory(string $directory,array $crypt_history){
	$check_path = sprintf("%s\%s",$directory,CHECKFILE);
	@file_put_contents($check_path, json_encode($crypt_history,JSON_PRETTY_PRINT));
}

/**
 *	Set the Last modification time of source file into the target file after process
 */
function keepLastModifiedTime(string &$source_file_path,string &$target_file_path) {
	touch($target_file_path,filemtime($source_file_path));
}

/**
 *	The CLI Countdown to inform the user for source file removing
 */
function rmCountDown(int $time_by_second=5) {
	echo "\t\033[91mRemoving orginal File on ";
	for(;$time_by_second>0;$time_by_second--){
		echo $time_by_second." ";
		sleep(1);
	}
	echo "\033[0m\n";
}

/**
 *	Get the given directory history
 */
function & getDirectoryCryptionHistory(string $directory) : array{
	$check_path = sprintf("%s\%s",$directory,CHECKFILE);
	$crypt_history = file_exists($check_path) ? json_decode(file_get_contents($check_path),true)	:	[];
	if(!is_array($crypt_history))
		$crypt_history = [];
	return $crypt_history;
}

/**
 *	Help users to findout are their entered key correct or not
 */
function isCryptionKeyValid(string $current_decrypted_file,string $current_decrypted_md5){
	list($directory,$file_name) = fileProperties($current_decrypted_file);
	$crypt_history = getDirectoryCryptionHistory($directory);
	$caller_crypto_method = debug_backtrace()[1]['function'];
	$out = false;
	switch ($caller_crypto_method) {
		case 'Encrypt':
			$crypt_history[$file_name] = $current_decrypted_md5;
			setDirectoryCryptionHistory($directory,$crypt_history);
			$out = true;
			break;
		case 'Decrypt':
			$orginal_file_md5 = $crypt_history[$file_name];
			$out = ( $orginal_file_md5 == $current_decrypted_md5 );
			break;
	}
	return $out;
}

/**
 *	Recturn the list of files matching the given pattern
 */
function getFilesByRegex(string &$regex) : array{
	return glob($regex);
	// $regex = str_replace("/","\\",$regex);
	// if(substr($regex, 0,2) == ".\\")
	// 	$regex = substr($regex, 2);
	// $files = scandir(dirname($regex));
	// $file_regex = substr($regex,strrpos($regex,"\\"));
	// $file_regex = $file_regex[0] == "\\" ? substr($file_regex, 1) : $file_regex;
	// $file_regex = str_replace(["*","+","\\","/"], ['.*',".+","\\\\","\\/"], $file_regex);
	// $needle_files = [];
	// foreach ($files as $key_32bit => $file) 
	// 	if(!is_dir($file) && preg_match("/$file_regex$/", $file))
	// 		$needle_files[] = dirname($regex)."\\".$file;
	// unset($files);
	// unset($file_regex);
	// return $needle_files;
}

/**
 *	Encrypting function
 */
function Encrypt(string &$file_path,string &$password){
	echo "\033[97mWaiting : file '$file_path' encryption in process !\033[0m\n";
	list($directory,$file_name) = fileProperties($file_path);
	if(!file_exists($directory."\\".PREFIX.$file_name)){
		$file_raw = file_get_contents($file_path);
		$encrypted_raw = openssl_encrypt($file_raw, METHOD, generateKey($password), OPENSSL_RAW_DATA,IV);
		if(isCryptionKeyValid($file_path, md5($file_raw))){
			$encrypted_path = $directory."\\".PREFIX.$file_name;
			file_put_contents($encrypted_path, $encrypted_raw);
			echo "\033[32mSuccess : File '$file_path' encrypted !\033[0m\n";
			unset($encrypted_raw);
			keepLastModifiedTime($file_path,$encrypted_path);
			rmCountDown();

			# Deleting Original File
			if(file_exists($file_path) && filesize($encrypted_path) > 0){
				@unlink($file_path);
				echo "\t\033[33mCaution : The raw file '$file_path' has been deleted !\033[0m\n";
			}
		}else{
			echo "\t\033[31mWarning : File '$file_path' could not be encrypted !\033[0m\n";
		}
		unset($file_raw);
	}else
		echo "\t\033[31mWarning : File '$file_path' also encrypted !\033[0m\n";
	echo "-\t-\t-\t-\t-\t-\t-\t-\n";
}

/**
 *	Decrypting function
 */
function Decrypt(&$crypted_file_path,&$password){
	echo "\033[97mWaiting : file '$crypted_file_path' decryption in process !\033[0m\n";
	list($directory,$crypted_file_name) = fileProperties($crypted_file_path);
	if(strpos($crypted_file_name, PREFIX) === 0){
		$decrypted_file_name = substr($crypted_file_name, strlen(PREFIX));
		$encrypted_raw = file_get_contents($crypted_file_path);
		$decrypted = openssl_decrypt($encrypted_raw, METHOD, generateKey($password), OPENSSL_RAW_DATA, IV);
		unset($encrypted_raw);
		if(isCryptionKeyValid($directory."\\".$decrypted_file_name,md5($decrypted))){
			$decrypted_path = $directory."\\".$decrypted_file_name;
			file_put_contents($decrypted_path, $decrypted);
			echo "\033[32mSuccess : File '$crypted_file_path' decrypted !\033[0m\n";
			unset($decrypted);
			keepLastModifiedTime($crypted_file_path,$decrypted_path);
			rmCountDown();

			# Deleting Original File
			if(file_exists($crypted_file_path) &&  filesize($decrypted_path) > 0){
				@unlink($crypted_file_path);
				echo "\t\033[33mCaution : The crypted file '$crypted_file_path' has been deleted !\033[0m\n";
			}
		}else
			echo "\t\033[31mWarning : File '$crypted_file_path' decryption failed !\033[0m\n";
	}else
		echo "\t\033[31mWarning : File '$crypted_file_path' also decrypted !\033[0m\n";
	echo "-\t-\t-\t-\t-\t-\t-\t-\n";	
}

#######################
/**
 *	Running commands
 */
if(count($argv) != 7){
	echo "Error : Not all the reqired fileds passed !\n" ;
	die($intro);
}

$args = (object)[ "method" => "", "pass" => "", "files" => "" ];

foreach ($argv as $key => $arg){
	if(($arg == "--method" or $arg == "-m") and isset($argv[$key+1]) and strpos($argv[$key+1], "-") !== 0)
		$args->method = $argv[$key+1];
	elseif(($arg == "--pass" or $arg == "-p") and isset($argv[$key+1]) and strpos($argv[$key+1], "-") !== 0)
		$args->pass = $argv[$key+1];
	elseif(($arg == "--files" or $arg == "-f") and isset($argv[$key+1]) and strpos($argv[$key+1], "-") !== 0)
		$args->files = (array)getFilesByRegex($argv[$key+1]);
}

if(empty($args->files))
	die("Fault : No existing file has given !");

switch (strtolower($args->method)) {
	case 'enc':
		echo "\033[34mEncryption has Started .... \033[0m\n";
		foreach ($args->files as $f)
			Encrypt($f,$args->pass);
		break;
	case 'dec':
		echo "\033[34mDecryption has Started .... \033[0m\n";
		foreach ($args->files as $f) 
			Decrypt($f,$args->pass);
		break;
	default:
		die("Fault : Method '{$args->method}' undefined!");
		break;
}

?>
