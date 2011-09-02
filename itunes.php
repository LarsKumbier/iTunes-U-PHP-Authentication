<?php
/**
 * Apple iTunes U transfer script based on the ITunesU.pl example script
 *
 * @package iTunes Authentication Class
 * @version 1.3 - 02/24/2011
 * 
 * @author  Written by Aaron Axelsen <axelsena@uww.edu>
 *          University of Wisconsin (Whitewater, USA)
 * @link    http://omega1.uww.edu/itunesu
 * 
 * @author  Extensions of version 1.3 by Lars Scheithauer <lars.scheithauer@fh-heidelberg.de>
 *          SRH Hochschule Heidelberg (Germany)
 * @link    https://github.com/derLars/iTunes-U-PHP-Authentication
 *
 * Information on iTunesU:
 * @see     http://deimos.apple.com/rsrc/doc//iTunesUAdministrationGuide/
 *
 *
 * REQUIREMENTS:
 *
 *	PHP: (Tested with 5.1.x and Newer)
 *	- php mhash support - http://mhash.sourceforge.net/
 *	- php curl support
 *
 *
 * CHANGELOG
 *
 *   1.3 (02/24/2011)
 *      - Proxy support
 *      - FIX: role definition in setupExample()
 *      - Error Handling through getLastError()
 *      - fluent interface design pattern for most public functions - enables a nice programming style like
 *              $itunes->setupExample()
 *                     ->setDebug(true)
 *                     ->setUser("John Doe", "jdoe@example.com", "jdoe", "12345")
 *                     ->add("Student@urn:mace:itunesu.com:sites:example.edu");
 *      - deprecated-docblocks for addAdminCredentials(), addStudentCredentials() and addInstructorCredentials()
 *      - PHP-docblocks extended
 *
 *   1.2 (10/29/2007)
 *      - Added config function - This will allow the user to pass in an associative array of keys and values which will be used to configure the class. Invalid keys which are passed in will trigger a E_USER_WARNING message.
 *        Example:
 *              $itunesConfig['roles']['administrator'] = 'Administrator@urn:mace:itunesu.com:sites:example.edu';
 *              $itunesConfig['roles']['student'] = 'Student@urn:mace:itunesu.com:sites:example.edu:classes';
 *              $itunesConfig['roles']['instructor'] = 'Instructor@urn:mace:itunesu.com:sites:example.edu:classes';
 *              $itunesConfig['siteURL'] = 'https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu';
 *              $itunesConfig['debugSuffix'] = '/abc1234';
 *              $itunesConfig['sharedSecret'] = 'STRINGOFTHIRTYTWOLETTERSORDIGITS';
 *  
 *        // Option 1	
 *            $itunes = new itunes($itunesConfig);
 * 
 *        // Option 2	
 *            $itunes = new itunes();
 *            $itunes->config($itunesConfig);
 * 	
 *      - Changed credentials setup - As part of the config function, roles are now contained in an associative array of keys and values. To add credentials, call the newly created add() function - $itunes->add('credentialname','uniquevalue');
 *      - addStudentCredential, addInstructorCredential, and addAdminCredential are now deprecated. Please convert your applications to use the new add() function
 *      - Improved configuration option notes and internal script documentation
 *      - Added function to setup DirectURL (No longer need to specify config variable) - used for launching iTunes U directly into a course
 *      - Added back pear functions if hash and curl are not available
 *      - Added setupExample() function - this will configure the class with the credentials provided by Apple to authenticate into their example instance
 *
 */

class itunes {

	/**
	 * @example https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu
	 * @var string
	 */
	private $siteURL;

	
	/**
	 * @example /abc1234
	 * @var string
	 */
	private $debugSuffix;

	
	/**
	 * @example STRINGOFTHIRTYTWOLETTERSORDIGITS
	 * @var string;
	 */
	private $sharedSecret;

	
	/**
	 * Array of credentials applied for the current user
	 *
	 * @var array
	 */
	private $credentials = array();

	
	/**
	 * Array of roles passed in with config options
	 *
	 * @var array
	 */
	private $roles = array();
	
	
	/**
	 * optional http_proxy to use
	 * 
	 * @var array
	 * @example $httpProxy = array (
	 *                  'host' => 'proxy.example.com',
	 *                  'port' => 8080,
	 *                  'user' => 'jdoe',
	 *                  'pass' => 'VeryVerySecret');
	 */
	private $httpProxy = array();
	
	
	/**
	 * contains the last error message, if any
	 * 
	 * @var string
	 * @var int
	 */
	private $lastError = null;
	private $lastErrNo = null;
	
	
	/**
	 * holds the debug status
	 * 
	 * @var bool
	 */
	private $debug = false;
	
	
	/**
	 * saves the response from itunes for later purposes
	 * 
	 * @var string
	 */
	private $itunesResponse = null;
	
	

	/**
	 * Create iTunes Object
	 * 
	 * @return itunes $this
	 */
	public function __construct($config = false) {
		# Set Debug to False
		$this->setDebug(false);

		# If options are passed in at construct time, setup options
		if ($config != false) {
			$this->config($config);
		}
		
		return $this;
	}

	
	
	/**
	 * Use Example Credentials
	 * This will setup the options to authenticate into Apple's example iTunes U instance
	 * 
	 * @return itunes $this
	 */
	public function setupExample() {
		# Site URL - used for basic logins
		$this->siteURL = 'https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu';

		# Debug Suffix - needed to authenticate for debugging
	    $this->debugSuffix = '/abc1234';

		# Shared Secret - needed for authentication
		$this->sharedSecret = 'STRINGOFTHIRTYTWOLETTERSORDIGITS';

		# Roles - array of roles used for credential strings - must correspond to what is set in iTunes U
		$this->roles['administrator'] = 'Administrator@urn:mace:itunesu.com:sites:example.edu';
	    $this->roles['student'] = 'Student@urn:mace:itunesu.com:sites:example.edu:classes';
	    $this->roles['instructor'] = 'Instructor@urn:mace:itunesu.com:sites:example.edu:classes';

		# Set domain
	    $this->setDomain();

		# Set Direct URL - used in conjunction with the handle (allows itunes U to launch directly into the specified course)
		$this->setDirectURL();
		
		return $this;
	}

	
	
	/**
	 * Set Configuration Options
	 * 
	 * Takes array as input, keys should correspond to variables above
	 *
	 * @param array $config iTunes configuration options passed into the class
	 * @return itunes $this
	 */
	public function config($config) {
		foreach ($config as $key=>$val) {
			if (property_exists($this, $key))
				$this->$key = $val;
			else
				trigger_error("Invalid config option: $key", E_USER_WARNING);
		}

		$this->setDomain();
		$this->setDirectURL();
		
		return $this;
	}

	
	
	/**
	 * Add credentials
	 *
	 * @param string $role Name of the role to add
	 * @param string $unique Unique identifier for a course (Not required for Admin)
	 * @return itunes $this
	 */
	public function add($role, $unique = -1) {
		if ($unique == -1)
			$this->addCredentials($this->roles[$role]);
		else
			$this->addCredentials($this->roles[$role].":$unique");
		
		return $this;
	}

	
	
	/**
	 * Add's admin credentials for a given user
	 * @deprecated - Convert to using array based credentials - add()
	 */
	public function addAdminCredentials() {
		$this->addCredentials($this->administratorCredential);
	}

	
	
	/**
	 * Add Student Credential for a given course
	 * @deprecated - Convert to using array based credentials - add()
	 */
	public function addStudentCredential($unique) {
		$this->addCredentials($this->studentCredential.":$unique");
	}

	
	
	/**
	 * Add Instructor Credential for a given course
	 * @deprecated - Convert to using style array credentials - add()
	 */
	public function addInstructorCredential($unique) {
		$this->addCredentials($this->instructorCredential.":$unique");
	}

	
	
	/**
	 * Set User Information
	 * 
	 * @return itunes $this
	 */
	public function setUser($name, $email, $netid, $userid) {
		$this->name = $name;
		$this->email = $email;
		$this->netid = $netid;
		$this->userid = $userid;
		return $this;
	}

	
	
	/**
	 * Set the Domain
	 *
	 * Takes the siteURL and splits off the destination, hostname and action path.
	 * 
	 * @return bool
	 */
	private function setDomain() {
		$tmpArray = split("/",$this->siteURL);
		$this->siteDomain = $tmpArray[sizeof($tmpArray)-1];
		$this->actionPath = preg_replace("/https:\/\/(.+?)\/.*/",'$1',$this->siteURL);
		$pattern = "/https:\/\/".$this->actionPath."(.*)/";
		$this->hostName = preg_replace($pattern,'$1',$this->siteURL);
		$this->destination = $this->siteDomain;
		return bool;
	}

	
	
	/**
	 * Set Direct URL
	 *
	 * Sets the Direct URL - If a handle is specified during the authentication process, this URL will be used to
	 * launch iTunes U directly into the specified course.
	 */
	private function setDirectURL() {
		$this->directSiteURL = "https://deimos.apple.com/WebObjects/Core.woa/BrowsePrivately/".$this->siteDomain;
	}
	
	

	/**
	 * Set the Handle
	 *
	 * Takes the handle as input and forms the get upload url string
	 * This is needed for using the API to upload files directly to iTunes U
	 * 
	 * @return itunes $this
	 */
	public function setHandle($handleIn) {
		$this->handle = $handleIn;
		$this->getUploadUrl = "http://deimos.apple.com/WebObjects/Core.woa/API/GetUploadURL/".$this->siteDomain.'.'.$this->handle;
		return $this;
	}

	
	
	/**
	 * Get Identity String
	 *
	 * Combine user identity information into an appropriately formatted string.
	 * take the arguments passed into the function copy them to variables
	 * 
	 * @return string
	 */
	private function getIdentityString() {
		# wrap the elements into the required delimiters.
		return sprintf('"%s" <%s> (%s) [%s]', $this->name, $this->email, $this->netid, $this->userid);
	}

	/**
	 * Add Credentials to Array
	 *
	 * Allows to push multiple credentials for a user onto the array
	 * 
	 * @return bool
	 */
	private function addCredentials($credentials) {
		array_push($this->credentials,$credentials);
		return true;
	}

	
	
	/**
	 * Get Credentials String
	 *
	 * this is equivalent to join(';', @_); this function is present
	 * for consistency with the Java example.
	 * concatenates all the passed in credentials into a string
	 * with a semicolon delimiting the credentials in the string.
	 * 
	 * @return string
	 */
	private function getCredentialsString() {
		#make sure that at least one credential is passed in
		if (sizeof($this->credentials) < 1)
			return false;
		return implode(";",$this->credentials);
	}
	
	

	/**
	 * Builds an authorization token to return to the apple Authentication service
	 *
	 * @return string
	 */
	private function getAuthorizationToken() {
		# Create a buffer with which to generate the authorization token.
		$buffer = "";

        # create the POST Content and sign it
    	$buffer .= "credentials=" . urlencode($this->getCredentialsString());
        $buffer .= "&identity=" . urlencode($this->identity);
        $buffer .= "&time=" . urlencode(mktime());

	        # returns a signed message that is sent to the server
		if (function_exists('hash_hmac'))
			$signature = hash_hmac('SHA256', $buffer, $this->sharedSecret);
		else {
    		require_once 'Message/Message.php';
    		$hmac = Message::createHMAC('SHA256', $this->sharedSecret);
    		$signature = $hmac->calc($buffer);
		}
	    	# append the signature to the POST content
		return sprintf("%s&signature=%s", $buffer, $signature);
	}
	
	

	/**
	 * Invoke Action
	 *
	 * Send a request to iTunes U and record the response.
	 * Net:HTTPS is used to get better control of the encoding of the POST data
	 * as HTTP::Request::Common does not encode parentheses and Java's URLEncoder
	 * does.
	 * 
	 * @param bool $echo=true - should this function return the response from iTunes to the client's browser?
	 */
	public function invokeAction($echo=true) {
		$this->identity = $this->getIdentityString();
		$this->token = $this->getAuthorizationToken();

		if (function_exists('curl_init')) {
			if ($this->debug)
				trigger_error('using curl', E_USER_NOTICE);
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $this->generateURL() . '?' . $this->token);
			curl_setopt($ch, CURLOPT_POST, 1);
			
			$this->curlSetProxy($ch, $this->httpProxy);

			if ($this->debug) {
				trigger_error("curl url to call: ".curl_getinfo($ch, CURLINFO_EFFECTIVE_URL), E_USER_NOTICE);
			}
			
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				
			if (($this->itunesResponse = curl_exec($ch)) !== false) {
				if ($echo) {
					echo $this->itunesResponse;
	                // Echo Javascript to clear contents of popup window
	                echo "<script type=\"text/javascript\">
	                <!--
	                document.getElementById('loading').innerHTML = '';
	                -->
	                </script>";
				}
				curl_close($ch);
				return true;
			} else {
				$this->setError(curl_error($ch), curl_errno($ch));
				curl_close($ch);
				return false;
			}
		} else {
			if ($this->debug)
				trigger_error('using HTTP_Request', E_USER_NOTICE);
			
        	require_once 'HTTP/Request.php';
            $req = &new HTTP_Request($this->generateURL());;
            $req->setMethod(HTTP_REQUEST_METHOD_POST);
            $req->addHeader("Content-Type","application/x-www-form-urlencoded");
            $req->addHeader("charset","UTF-8");
            $req->addRawPostData($this->token, true);
            if (!empty($this->httpProxy)) {
            	if ($this->debug)
					trigger_error('Setting Proxy information ('.implode(';', $this->httpProxy).')', E_USER_NOTICE);
            	$req->setProxy($this->httpProxy['host'], $this->httpProxy['port'], $this->httpProxy['user'], $this->httpProxy['pass']);
            }

            $x = $req->sendRequest();

            if (PEAR::isError($x)) {
                $this->lastError = $x->getMessage();
                if ($echo)
                	echo $this->lastError;
                // Return false if error
                return false;
            } else {
                if ($echo) {
	            	echo $req->getResponseBody();
	                // Echo Javascript to clear contents of popup window
	                echo "<script type=\"text/javascript\">
	                <!--
	                document.getElementById('loading').innerHTML = '';
	                -->
	                </script>";
                }
                // Return true if success
                return true;
            }
		}
	}

	
	
	/**
	 * Auth and Upload File to iTunes U
	 *
	 * This method is said to not be as heavily tested by apple, so you may have
	 * unexpected results.
	 *
	 * @param string $fileIn - full system path to the file you desire to upload
	 */
	public function uploadFile($fileIn) {
        $this->identity = $this->getIdentityString();
        $this->token = $this->getAuthorizationToken();

		// Escape the filename
		$f = escapeshellcmd($fileIn);

		// Contact Apple and Get the Upload URL
		$upUrl = curl_init($this->getUploadUrl.'?'.$this->token);
		curl_setopt($upUrl, CURLOPT_RETURNTRANSFER, true);
		
		$this->curlSetProxy($upUrl, $this->httpProxy);
		
		$uploadURL = curl_exec($upUrl);
		
		if (curl_errno($upUrl) !== 0)
			$this->setError(curl_error($upUrl), curl_errno($upUrl));
		
		$http_code = curl_getinfo($upUrl ,CURLINFO_HTTP_CODE);

		curl_close($upUrl);

		print $http_code;
		print "<br /><br />$uploadURL";
		if (!empty($this->lastError)) {
			print "<br /><br />".$this->lastError."(".$this->lastErrNo.")";
		}

		# Currently not working using php/curl functions.  For now, we are just going to echo a system command .. see below
		#// Push out the designated file to iTunes U
		#// Build Post Fields
		#$postfields = array("file" => "@$fileIn");

		#$pushUrl = curl_init($uploadURL);
		#curl_setopt($pushUrl, CURLOPT_FAILONERROR, 1);
		#curl_setopt($pushUrl, CURLOPT_FOLLOWLOCATION, 1);// allow redirects
		#curl_setopt($pushUrl, CURLOPT_VERBOSE, 1);
		#curl_setopt($pushUrl, CURLOPT_RETURNTRANSFER, true);
		#curl_setopt($pushUrl, CURLOPT_POST, true);
		#curl_setopt($pushUrl, CURLOPT_POSTFILEDS, $postfields);
		#$output = curl_exec($pushUrl);
		#$error = curl_error($pushUrl);
		#$http_code = curl_getinfo($pushUrl, CURLINFO_HTTP_CODE);

		#curl_close($pushUrl);

		#print "<br/>";
		#print $http_code;
		#print "<br /><br />$output";
		#if ($error) {
		#   print "<br /><br />$error";
		#}

		// Set the php time limit higher so it doesnt time out.
		set_time_limit(1200);

		// System command to initiate curl and upload the file. (Temp until I figure out the php curl commands to do it)
		$command = "curl -S -F file=@$f $uploadURL";

		echo "<br/><br/>";
		echo $command;
		exec($command, $result, $error);
		if ($error) {
			echo "I'm busted";
		} else {
			print_r($result);
		}
		echo $command;
	}
	
	

	/**
	 * Set Debugging
	 *
	 * @param bool Enable/Disable debugging of iTunes U Authentication
	 * @return itunes $this
	 */
	public function setDebug($bool) {
		if ($bool) {
			$this->debug = true;
		} else {
			$this->debug = false;
		}
		return $this;
	}
	
	

	/**
	 * Generate Site URL
	 *
	 * Append debug suffix to end of url if debugging is enabled
	 */
	private function generateURL() {
		if ($this->debug) {
			return $this->siteURL.$this->debugSuffix;
		} elseif ($this->isHandleSet()) {
			return $this->directSiteURL.'.'.$this->handle;
		} else {
			return $this->siteURL;
		}
	}
	
	

	/**
	 * Check to see if the handle is set
	 */
	private function isHandleSet() {
		if (isset($this->handle))
			return true;
		else
			return false;
	}
	
	
	
	/**
	 * sets the error message
	 * 
	 * @param string $message
	 * @param int    $errId
	 */
	private function setError($message, $errId=null) {
		$this->lastError = $message;
		$this->lastErrNo = $errId;
	}
	
	
	
	/**
	 * returns the last error message, if any
	 */
	private function getLastError() {
		if (empty($this->lastError))
			return false;
		return $this->lastError;
	}
	
	
	
	/**
	 * sets the proxy options, if amy are given
	 *
	 * @param curl  $ch
	 * @param array $proxyconfig
	 */
	private function curlSetProxy($ch, $proxyconfig) {
		if (!empty($proxyconfig)) {
			if ($this->debug)
				trigger_error('Setting Proxy information ('.implode(';', $proxyconfig).')', E_USER_NOTICE);
			curl_setopt($ch, CURLOPT_PROXY, $proxyconfig['host']);
			curl_setopt($ch, CURLOPT_PROXYPORT, (array_key_exists('port', $proxyconfig) ? (int)$proxyconfig['port'] : 8080));
			if (array_key_exists('user', $proxyconfig) && (array_key_exists('pass', $proxyconfig))) {
				curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyconfig['user'].':'.$proxyconfig['pass']);
			}
		}
	}
	
	
	
	/**
	 * returns the itunesResponse
	 * 
	 * @return string
	 */
	public function getITunesResponse() {
		return $this->itunesResponse;
	}
	
	
	
	/**
	 * extracts the ITMSS-Link, used from the browser to identify a request to start iTunes
	 * 
	 * @return (bool|string) $url - the found itmss-link
	 */
	public function getItmssUrl() {
		if ($this->itunesResponse === null) {
			$this->lastError = 'There is no response from Apple saved - did you call invokeAction()?';
			$this->lastErrNo = -1;
			return false;
		}
		
		if (!preg_match('/\'(itmss\:\/\/.*)\'/i', $this->itunesResponse, $matches))
			return false;
		
		// parse_url throws an E_WARNING, if the response was invalid
		if (@parse_url($matches[1]) !== false)
			return $matches[1];
		
		return false;
	}
}
?>
