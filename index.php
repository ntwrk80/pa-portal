<?php
//base auth code from http://www.abrandao.com/2018/08/php-authenticate-users-with-windows-server-active-directory/
error_reporting(E_ALL);
ini_set('display_errors', 'On');
define('DOMAIN_FQDN', 'example.contoso.com'); //Replace with REAL DOMAIN FQDN
define('LDAP_SERVER', '192.0.20.5');  //Replace with REAL LDAP SERVER Address
define('API_URL', 'https://192.0.20.10/api/?type=user-id'); //Replace with REAL PA MGMT Address
define('API_KEY', 'CHANGEME'); //Replace with the API key from your PaloAlto firewall.
define('TITLE', 'PaloAlto Login'); //Change to suit.

function getRealIpAddr(){
 if ( !empty($_SERVER['HTTP_CLIENT_IP']) ) {
  // Check IP from internet.
  $ip = $_SERVER['HTTP_CLIENT_IP'];
 } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) ) {
  // Check IP is passed from proxy.
  $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
 } else {
  // Get IP address from remote address.
  $ip = $_SERVER['REMOTE_ADDR'];
 }
 return $ip;
}


$ipaddress = getRealIPAddr();


//Basic Login verification
if (isset($_POST['submit']))
{
    $username = rtrim(strip_tags($_POST['username']));
    $user = rtrim(strip_tags($_POST['username'])) .'@'. DOMAIN_FQDN;
    $pass = rtrim(stripslashes($_POST['password']));
    
    $conn = ldap_connect("ldap://". LDAP_SERVER ."/");
    error_log("Hello",3,"/tmp/myerror.log");
    if (!$conn)
            $err = 'Could not connect to LDAP server';

    else
        {
	//        define('LDAP_OPT_DIAGNOSTIC_MESSAGE', 0x0032);  //Already defined in PHP 5.x  versions
            
	        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		    ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);

        $bind = @ldap_bind($conn, $user, $pass);

        ldap_get_option($conn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);
        error_log($extended_error,0);
        if (!empty($extended_error))
	        {
		            $errno = explode(',', $extended_error);
			                $errno = $errno[2];
					            $errno = explode(' ', $errno);
						                $errno = $errno[2];
								            $errno = intval($errno);

            if ($errno == 532)
	                    $err = 'Unable to login: Password expired';
			            }

        elseif ($bind)
	        {
		      //determine the LDAP Path from Active Directory details
                $base_dn = array("CN=Users,DC=". join(',DC=', explode('.', DOMAIN_FQDN)),
                                 "OU=Users,OU=People,DC=". join(',DC=', explode('.', DOMAIN_FQDN)));
                error_log("before ldap_search",3,"/tmp/myerror.log");
                $result = ldap_search(array($conn,$conn), $base_dn, "(cn=$user)");
                error_log("after ldap_search",3,"/tmp/myerror.log");
                    if (!count($result))
	                    $err = 'Result: '. ldap_error($conn);

                    else
	                {
                        error_log( "Entering success",3,"/tmp/myerror.log");
                        
					        /* Do your post login code here */
                            $domain = DOMAIN_FQDN;
                            $input_xml= <<<XML
<uid-message> 
     <version>1.0</version> 
     <type>update</type> 
     <payload> 
          <login> 
               <entry name="$user" ip="$ipaddress" timeout="20"> 
               </entry> 
          </login> 
     </payload> 
</uid-message>
XML;
                            $curl = curl_init(API_URL);
                            curl_setopt($curl, CURLOPT_POST, true);
                            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
                            curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
                            $post = array(
                                'key' => API_KEY,
                                'cmd' => $input_xml);
                  
                            curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
                            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
                            error_log("\nBefore Curl_exec\n",3,"/tmp/myerror.log");
                            $result = curl_exec($curl);
                            error_log("\nAfter Curl_exec\n",3,"/tmp/myerror.log");
                            if (curl_errno($curl)){
                                error_log(curl_error($curl),3,"/tmp/myerror.log");
                                //throw new Exception(curl_error($curl));
                            }
                            curl_close($curl);
                            



                            
						            }
							            }
								        }

    // session OK, redirect to home page
        if (isset($_SESSION['redir']))
	    {
	            header('Location: /');
		            exit();
			        }

    elseif (!isset($err)) $err = 'Result: '. ldap_error($conn);

    ldap_close($conn);
    }
    ?>
    <!DOCTYPE html>
    <head>
    <title>PaloAlto Firewall User-ID</title>
    </head>
    <body>
    <div align="center">
    <h3><?php echo TITLE?></h3>

<div style="margin:10px 0;"></div>
<div title="Login"  id="loginbox">
    <div style="padding:10px 0 10px 60px">
        <form action="<?php echo $_SERVER['PHP_SELF'] ?>" id="login" method="post">
	        <table style='font-family:"Courier New", Courier, monospace; font-size:150%'><?php if (isset($err)) echo '<tr><td colspan="2" class="errmsg">'. $err .'</td></tr>'; ?>
		            <tr>
			           <td>Login:</td><td><input type="text" name="username" autocomplete="off"/></td>
                    </tr>
					<tr>
					   <td>Password:</td><td><input type="password" name="password"  autocomplete="off"/></td>
					</tr>
			</table>
			<input class="button" type="submit" name="submit" value="Login" />
		</form>
	</div>
</div>
</div>
</body>
</html>



