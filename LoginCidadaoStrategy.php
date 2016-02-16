<?php
/**
 * Do strategy for Opauth
 *
 * More information on Opauth: http://opauth.org
 *
 * @link         http://opauth.org
 * @package      Opauth.LoginCidadaoStrategy
 * @license      MIT License
 */

/**
 * Do strategy for Opauth
 * 
 * @package			Opauth.LoginCidadao
 */
class LoginCidadaoStrategy extends OpauthStrategy {
	
	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('client_id', 'client_secret');
	
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'response_type');
	
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
		'scope' => 'email public_profile',
		'response_type' => 'code'
	);
	
	/**
	 * Auth request
	 */
	public function request() {
		$url = 'http://minha.redelivre.ethymos.com.br/wp-content/themes/login-cidadao/web/app_dev.php/oauth/v2/auth';
		$params = array(
			'client_id' => $this->strategy['client_id'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			
		);

		foreach ($this->optionals as $key) {
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}
		$this->clientGet($url, $params);
	}
	
	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback() {
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
			$code = $_GET['code'];
			$url = 'http://minha.redelivre.ethymos.com.br/wp-content/themes/login-cidadao/web/app_dev.php/oauth/v2/token';
			
			$params = array(
				'code' => $code,
				'client_id' => $this->strategy['client_id'],
				'client_secret' => $this->strategy['client_secret'],
				'redirect_uri' => $this->strategy['redirect_uri'],
				'grant_type' => 'authorization_code',
			);
			if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];
			
			$response = $this->serverPost($url, $params, null, $headers);
			
			$results = json_decode($response);
			
			if (!empty($results) && isset($results->access_token))
			{
				$user = $this->user($results->access_token);
				
				$this->auth = array(
					'uid' => $user['id'],
					'info' => array(
						'email' => $user['email'],
						'profile_picture_url' => $user['profile_picture_url']
					),
					'credentials' => array(
						'token' => $results->access_token
					),
					'raw' => $user
				);
				
				if(array_key_exists('given_name', $user))
				{
					$this->auth['info']['display_name'] = $user['given_name'];
					$this->mapProfile($user, 'name', 'info.display_name');
				}
				if(array_key_exists('first_name', $user))
				{
					$this->auth['info']['first_name'] = $user['first_name'];
					$this->mapProfile($user, 'first_name', 'info.first_name');
				}
				
        		//$this->mapProfile($user, 'last_name', 'info.last_name');
				$this->mapProfile($user, 'email', 'info.email');
				$this->mapProfile($user, 'avatar_url', 'info.profile_picture_url');
				
				$this->callback();
			}
			else {
				$error = array(
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response,
						'headers' => $headers
					)
				);

				$this->errorCallback($error);
			}
		}
		else {
			$error = array(
				'code' => 'oauth2callback_error',
				'raw' => $_GET
			);
			
			$this->errorCallback($error);
		}
	}
	
	/**
	 * Queries Do API for user info
	 *
	 * @param string $access_token 
	 * @return array Parsed JSON results
	 */
	private function user($access_token) {
		$user = $this->serverGet('http://minha.redelivre.ethymos.com.br/wp-content/themes/login-cidadao/web/app_dev.php/api/v1/person.json', array('access_token' => $access_token), null, $headers);
		if (!empty($user)) {
			return $this->recursiveGetObjectVars(json_decode($user));
		}
		else {
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query the Do API for user information',
				'raw' => array(
					'response' => $user,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
		}
	}
}
