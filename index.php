<?php
ini_set('display_errors', 1); 
require_once 'Poutsch.class.php';

// Your credentials
$app_id = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
$app_secret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

// The specified scopes you want, spaces separated
$scopes = 'profile friends';


try{

	$poutsch = new Poutsch($app_id, $app_secret, $scopes);

	$data = $poutsch->getProfile();

	var_dump($data);

}catch(Exception $e){
	echo $e->getMessage();
}




?>