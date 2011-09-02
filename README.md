1. Introduction
===============
iTunes-U is the university section of Apple's iTunes and provides public and private channels for the educational sector. The authentication is handled on the client side and the user is redirected to iTunes with a token containing his proof of authentication. The authorization is handled on the iTunes servers depending on the the roles defined in the token.


2. Quickstart
=============
$itunes = new itunes();
$itunes->setExample()
       ->invokeAction(true);


3. Usage
========
At first, you should go through the usual procedure of authenticating a user, e.g. against your LDAP or ActiveDirectory.

Your general setup works by building a configuration array with the provided data by your apple representative:

	$config['siteURL'] = 'https://deimos.apple.com/WebObjects/Core.woa/Browse/example.edu';
	$config['debugSuffix'] = '/abc1234';
	$config['sharedSecret'] = 'STRINGOFTHIRTYTWOLETTERSORDIGITS';

For authorization, you also have to add the possible MACEs, e.g.

	$config['roles']['administrator'] = 'Administrator@urn:mace:itunesu.com:sites:example.edu';
	$config['roles']['student']       = 'Student@urn:mace:itunesu.com:sites:example.edu:classes';
	$config['roles']['instructor']    = 'Instructor@urn:mace:itunesu.com:sites:example.edu:classes';
				 
Now just instantiate a new object with the configuration as argument:

	$itunes = new itunes($config);

After this, you may now add the details of the authenticated user and finally call the invokeAction()-method to redirect the user to the itunes-U-page, in which an itmss://-link will be generated to open up Apple's iTunes with the appropriate iTunes-U page:
	
	$itunes->setUser($fullname, $mailaddress, $networkId, $userId)
	       ->add('student');
	$itunes->invokeAction(true);


4. Methods and API
==================
All methods are docblocked and are pretty self-explanatory. 


5. License and Credits
======================
This library was originally written by Aaron Axelsen (axelsena@uww.edu) and extended by me, Lars Scheithauer (lars.scheithauer@fh-heidelberg.de). As I was unable to get a reply from Aaron on my request for merging my changes, I took the liberty of forking it on github.

The original package does not contain any licensing information, so I consider it to be public domain. However, please give credit, where credit is due.



