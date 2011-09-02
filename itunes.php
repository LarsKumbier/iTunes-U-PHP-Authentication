<?php
##############################################
#
# iTunes Authentication Class
# URL: http://omega1.uww.edu/itunesu
# Version: 1.2 - 10/29/2007
#
# Written by Aaron Axelsen - axelsena@uww.edu
# University of Wisconsin - Whitewater
#
# Class based on the Apple provided ITunesU.pl
# example script.
#
# REQUIREMENTS:
#
#	PHP: (Tested with 5.1.x and Newer)
#	- php mhash support - http://mhash.sourceforge.net/
#	- php curl support
#
#
##############################################

class itunes {

	/**
	* https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu
	*
	* @var string
	*/
	private $siteURL;

	/**
	* /abc1234
	*
	* @var string
	*/
	private $debugSuffix;

	/**
	* STRINGOFTHIRTYTWOLETTERSORDIGITS
	*
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
	* Create iTunes Object
	*/
	public function __construct($config = false) {
		# Set Debug to False
		$this->setDebug(false);

		# If options are passed in at construct time, setup options
		if ($config != false) {
			$this->config($config);
		}
	}

	/**
	* Use Example Credentials
	* This will setup the options to authenticate into Apple's example iTunes U instance
	*/
	public function setupExample() {
		# Site URL - used for basic logins
		$this->siteURL = 'https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu';

		# Debug Suffix - needed to authenticate for debugging
	      	$this->debugSuffix = '/abc1234';

		# Shared Secret - needed for authentication
		$this->sharedSecret = 'STRINGOFTHIRTYTWOLETTERSORDIGITS';

		# Roles - array of roles used for credential strings - must correspond to what is set in iTunes U
		$this->role['administrator'] = 'Administrator@urn:mace:itunesu.com:sites:example.edu';
	      	$this->role['student'] = 'Student@urn:mace:itunesu.com:sites:example.edu:classes';
	      	$this->role['instructor'] = 'Instructor@urn:mace:itunesu.com:sites:example.edu:classes';

		# Set domain
	      	$this->setDomain();

		# Set Direct URL - used in conjunction with the handle (allows itunes U to launch directly into the specified course)
		$this->setDirectURL();
	}

	/**
	* Set Configuration Options
	* Takes array as input, keys should correspond to variables above
	*
	* @config array $config iTunes configuration options passed into the class
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
	}

	/**
	* Add credentials
	*
	* @param string $role Name of the role to add
	* @param string $unique Unique identifier for a course (Not required for Admin)
	*/
	public function add($role,$unique = -1) {
		if ($unique == -1)
			$this->addCredentials($this->roles[$role]);
		else
			$this->addCredentials($this->roles[$role].":$unique");
	}

	/**
	* Add's admin credentials for a given user
	* DEPRECATED - Convert to using array based credentials - add()
	*/
	public function addAdminCredentials() {
		$this->addCredentials($this->administratorCredential);
	}

	/**
	* Add Student Credential for a given course
	* DEPRECATED - Convert to using array based credentials - add()
	*/
	public function addStudentCredential($unique) {
		$this->addCredentials($this->studentCredential.":$unique");
	}

	/**
	* Add Instructor Credential for a given course
	* DEPRECATED - Convert to using style array credentials - add()
	*/
	public function addInstructorCredential($unique) {
		$this->addCredentials($this->instructorCredential.":$unique");
	}

	/**
	* Set User Information
	*/
	public function setUser($name, $email, $netid, $userid) {
		$this->name = $name;
		$this->email = $email;
		$this->netid = $netid;
		$this->userid = $userid;
		return true;
	}

	/**
	* Set the Domain
	*
	* Takes the siteURL and splits off the destination, hostname and action path.
	*/
	private function setDomain() {
		$tmpArray = split("/",$this->siteURL);
		$this->siteDomain = $tmpArray[sizeof($tmpArray)-1];
		$this->actionPath = preg_replace("/https:\/\/(.+?)\/.*/",'$1',$this->siteURL);
		$pattern = "/https:\/\/".$this->actionPath."(.*)/";
		$this->hostName = preg_replace($pattern,'$1',$this->siteURL);
		$this->destination = $this->siteDomain;
		return true;
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
	*/
	public function setHandle($handleIn) {
		$this->handle = $handleIn;
		$this->getUploadUrl = "http://deimos.apple.com/WebObjects/Core.woa/API/GetUploadURL/".$this->siteDomain.'.'.$this->handle;
		return true;
	}

	/**
	* Get Identity String
	*
	* Combine user identity information into an appropriately formatted string.
	* take the arguments passed into the function copy them to variables
	*/
	private function getIdentityString() {
		# wrap the elements into the required delimiters.
		return sprintf('"%s" <%s> (%s) [%s]', $this->name, $this->email, $this->netid, $this->userid);
	}

	/**
	* Add Credentials to Array
	*
	* Allows to push multiple credientials for a user onto the array
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
	*/
	private function getCredentialsString() {
		#make sure that at least one credential is passed in
		if (sizeof($this->credentials) < 1)
			return false;
		return implode(";",$this->credentials);
	}

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
	*/
	public function invokeAction() {
		$this->identity = $this->getIdentityString();
		$this->token = $this->getAuthorizationToken();

		if (function_exists('curl_init')) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $this->generateURL() . '?' . $this->token);
			curl_setopt($ch, CURLOPT_POST, 1);

			if (curl_exec($ch)) {
		                // Echo Javascript to clear contents of popup window
        		        echo "<script type=\"text/javascript\">
                		<!--
	                	document.getElementById('loading').innerHTML = '';
        	        	-->
                		</script>";
				curl_close($ch);
				return true;
			} else {
				curl_close($ch);
				return false;
			}
		} else {
        		require_once 'HTTP/Request.php';
            		$req = &new HTTP_Request($this->generateURL());;
            		$req->setMethod(HTTP_REQUEST_METHOD_POST);
            		$req->addHeader("Content-Type","application/x-www-form-urlencoded");
            		$req->addHeader("charset","UTF-8");
            		$req->addRawPostData($this->token, true);

            		$x = $req->sendRequest();

            		if (PEAR::isError($x)) {
                		echo $x->getMessage();
                		// Return false if error
                		return false;
            		} else {
                		echo $req->getResponseBody();
                		// Echo Javascript to clear contents of popup window
                		echo "<script type=\"text/javascript\">
                		<!--
                		document.getElementById('loading').innerHTML = '';
                		-->
                		</script>";
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
	* $fileIn - full system path to the file you desire to upload
	*/
	public function uploadFile($fileIn) {
                $this->identity = $this->getIdentityString();
                $this->token = $this->getAuthorizationToken();

		// Escape the filename
		$f = escapeshellcmd($fileIn);

		// Contact Apple and Get the Upload URL
		$upUrl = curl_init($this->getUploadUrl.'?'.$this->token);
		curl_setopt($upUrl, CURLOPT_RETURNTRANSFER, true);
		$uploadURL = curl_exec($upUrl);

		$error = curl_error($upUrl);
		$http_code = curl_getinfo($upUrl ,CURLINFO_HTTP_CODE);

		curl_close($upUrl);

                print $http_code;
                print "<br /><br />$uploadURL";
                if ($error) {
                   print "<br /><br />$error";
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
	* Enable/Disable debugging of iTunes U Authentication
	*/
	public function setDebug($bool) {
		if ($bool) {
			$this->debug = true;
		} else {
			$this->debug = false;
		}
		return true;
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
}
?>
