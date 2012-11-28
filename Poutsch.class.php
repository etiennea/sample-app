<?php
define(DEBUG, false);

class Poutsch{
	private $access_token,
			$refresh_token,
			$access_token_expire,
			$app_id,
			$app_secret;


	public function __construct($app_id, $app_secret, $scopes){
		session_start();
		$this->app_id = $app_id;
		$this->app_secret = $app_secret;
		$this->scopes = $scopes;
				// If the state is auth, we are getting the server response after the user authorization
		if(isset($_GET['state']) && $_GET['state'] == 'auth'){
			// An error ocurred
			if(isset($_GET['error'])){
				// Specific error handler
				if($_GET['error'] == 'access_denied'){
					throw new Exception ('User has refused to grant access to app');
				}else{ // global error handler
					throw new Exception (urldecode($_GET['error_description']));
				}
			}
			// We can now obtain an access token thanks to the authorization_code
			$this->getAccessToken($_GET['code']);
		}
		// We check if we already have an access token
		else if(!isset($_SESSION['access_token'])){
			// Not logged in, we redirect the user in order to have his authorization
			header('location:'.'http://poutsch.com/authorize?app_id='.$this->app_id.'&response_type=code&state=auth&scope='.$this->scopes);
		}else{
			// We are logged

			// Check if the token is still ok
			if($_SESSION['set_time'] + $_SESSION['expires_in'] < time()){
				// If expired, we refresh it
				$this->refresh_token(); // Refresh it;
			}
		}
	}

	public function getProfile(){
		$data = array();
		$returnData = $this->request('http://poutsch.com/api/v1/users/me', $data, 'GET', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'][0];
	}

	public function getComments($qid){
		$data = array();
		$returnData = $this->request('http://poutsch.com/api/v1/questions/'.$qid.'/comments', $data, 'GET', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);
		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}

	public function postComment($qid, $comment){
		$data = array();
		$data['post']['comment'] = $comment;

		$returnData = $this->request('http://poutsch.com/api/v1/questions/'.$qid.'/comment', $data, 'POST', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}

	public function postReply($cid, $reply){
		$data = array();

		$data['post']['reply'] = $reply;

		$returnData = $this->request('http://poutsch.com/api/v1/comments/'.$cid.'/reply', $data, 'POST', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}
	public function getReply($scid){
		$data = array();



		$returnData = $this->request('http://poutsch.com/api/v1/comments/replies/'.$scid, $data, 'GET', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}

	public function deleteReply($rid){
		$data = array();

		$returnData = $this->request('http://poutsch.com/api/v1/comments/replies/'.$rid.'/delete', $data, 'POST', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}

	public function deleteComment($cid){
		$data = array();

		$returnData = $this->request('http://poutsch.com/api/v1/comments/'.$cid.'/delete', $data, 'POST', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting data: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}


	public function getOpinions(){
		$data = array();
		$returnData = $this->request('http://poutsch.com/api/v1/users/me/opinions', $data, 'GET', $_SESSION['access_token']);
		$returnData = $this->parseResponse($returnData);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting accessToken: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		return $returnData['response'];
	}


	private function refresh_token(){
		$data['post'] = array(
	        'grant_type' => urlencode('refresh_token'),
	        'app_id' => urlencode($this->app_id),
	        'refresh_token' => urlencode($_SESSION['refresh_token']),
	        'app_secret' => urlencode($this->app_secret)
	    );
		$responseText = $this->request('http://poutsch.com/api/v1/oauth/access_token', $data, 'POST');

		$returnData = $this->parseResponse($responseText);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting accessToken: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}

		// We store the token informations
		$_SESSION['access_token'] = $returnData['response']['access_token'];
		$_SESSION['refresh_token'] = $returnData['response']['refresh_token'];
		$_SESSION['expires_in'] = $returnData['response']['expires_in'];
		$_SESSION['set_time'] = time();
	}
	public function getAccessToken($code){
		$data['post'] = array(
	        'grant_type' => urlencode('authorization_code'),
	        'app_id' => urlencode($this->app_id),
	        'code' => urlencode($_GET['code']),
	        'app_secret' => urlencode($this->app_secret),
	    );
		$responseText = $this->request('http://poutsch.com/api/v1/oauth/access_token', $data, 'POST');

		$returnData = $this->parseResponse($responseText);

		if($returnData['meta'] != '200'){
			throw new Exception('Error while getting accessToken: '.$returnData['error']['error_name'].' ('.$returnData['error']['id'].') '.$returnData['error']['error_details']);
		}
		// We store the token informations
		$_SESSION['access_token'] = $returnData['response']['access_token'];
		$_SESSION['refresh_token'] = $returnData['response']['refresh_token'];
		$_SESSION['expires_in'] = $returnData['response']['expires_in'];
		$_SESSION['set_time'] = time();
	}

	private function parseResponse($responseText){

		if(!$responseText){
			throw new Exception('The request went wrong.');
		}
		if(DEBUG){
			echo $responseText;
		}

		// Parse json into an associative array
		$returnData = json_decode($responseText, true);

		if(!$returnData){
			throw new Exception('JSON couldnt be decoded.');
		}
		return $returnData;
	}
	private function request($url, $data, $method, $token = null, $debug=false){
		$post_fields_string = null;
		$get_fields_string = null;

		// We build the post string
		if($data && isset($data['post']) && count($data['post'])){
			$post_fields_string ='';
			foreach($data['post'] as $key=>$value){
				$post_fields_string .= $key.'='.urlencode($value).'&'; 
			}
			rtrim($post_fields_string, '&');
		}


		// We add the token to the get string
		if($token){
			$data['get']['access_token'] = $token;
		}

		// We build the get string
		if($data && isset($data['get']) && count($data['get'])){
			$get_fields_string ='';

			foreach($data['get'] as $key=>$value){
				$get_fields_string .= $key.'='.urlencode($value).'&'; 
			}
			rtrim($get_fields_string, '&');
		}

		// We add the '?'
		if($get_fields_string){
			$firstCar = '&';
			if(!strpos($url, '?')){
				$firstCar = '?';
			}
			$url .= $firstCar .$get_fields_string;
		}

		// Curl initiation
		$ch = curl_init($url); 

		if($method == 'POST' && $post_fields_string){
			curl_setopt($ch, CURLOPT_POST, count($data['post']));
			curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields_string);
		}

		curl_setopt($ch, CURLOPT_FRESH_CONNECT, true); 

		if (preg_match('`^https://`i', $url)) 
		{
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0); 
		}

		if(DEBUG){
			curl_setopt($ch, CURLOPT_HEADER, true);
			curl_setopt($ch, CURLOPT_VERBOSE, true);
		}

		

		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 

		$page_content = curl_exec($ch);

			
		if(!$page_content){
			die('Error: "' . curl_error($ch) . '" - Code: ' . curl_errno($ch));
		}
		curl_close($ch);

		return $page_content;
	}
}
