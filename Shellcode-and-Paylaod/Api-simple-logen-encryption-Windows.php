<?php 

    /*
        Author Jieyab89 
    */

    if(isset($_POST['data'])){
     
        $f = fopen('users/'.date('d-m-Y-H:i:s').'.txt', 'w');
        fwrite($f, $_POST['data']);
        
        if(fclose($f)){
            echo json_encode(['status' => 'success']);
        }else{
            
            echo json_encode(['status' => 'error']);
        }   
    }        

?>