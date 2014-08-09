orbini-auth-radius
==================

Zend Framework 1 adapter to authenticate on RADIUS servers

Installation
------------

To install simply copy the library/Orbini directory into the same directory as your Zend Framework and
register it using Zend_Loader::registerNamespace

Usage
-----

Simply instantiate the Orbini_Auth_Adapter_Radius class specifying the desired servers and pass it to Zend_Auth:

    //Create our adapter passing one server (up to 10 can be passed)
    $adapter = new Orbini_Auth_Adapter_Radius(
        array('servers' => array(
            array(
                'hostname' => 'localhost',
                'port'     => 1812,
                'secret'   => 'mysecret',
                'timeout'  => 15,
                'maxTries' => 1
            )
        )),
        $username,
        $password
    );

    //Get Zend_Auth Singleton instance
    $auth = Zend_Auth::getInstance()

    //Authenticate
    $result = $auth->authenticate($adapter);



